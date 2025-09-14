package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"git.gammaspectra.live/P2Pool/consensus/v4/monero/client/zmq"
	"git.gammaspectra.live/P2Pool/consensus/v4/types"
	"git.gammaspectra.live/P2Pool/monero-highway/internal/highway/checkpoint"
	"github.com/goccy/go-yaml"
)

func main() {
	rpcUrl := flag.String("rpc", "http://127.0.0.1:18081", "Monero RPC server URL. Can be restricted")
	zmqAddr := flag.String("zmq", "tcp://127.0.0.1:18083", "Monero ZMQ-PUB server address")

	pushConfigPath := flag.String("push-config", "", "Path to YAML file to push records")
	checkpointStatePath := flag.String("checkpoint-state", "checkpoints.txt", "File where to save checkpoint state. Directory where it is emplaced must be writable and on same mount")
	checkpointDepth := flag.Uint64("checkpoint-depth", 2, "Depth from tip to place checkpoints at. Depth of 2, means tip height of 100 will checkpoint 98")

	flag.Parse()

	httpClient := &http.Client{
		Transport: &http.Transport{},
		Timeout:   time.Second * 30,
	}

	dialer := &net.Dialer{
		Timeout: time.Second * 10,
	}

	var checkpointers []checkpoint.Config

	if *pushConfigPath != "" {
		pushConfigData, err := os.ReadFile(*pushConfigPath)
		if err != nil {
			slog.Error("Failed to read push config", "err", err)
			panic(err)
		}
		err = yaml.NewDecoder(bytes.NewReader(pushConfigData), yaml.UseJSONUnmarshaler()).Decode(&checkpointers)
		if err != nil {
			slog.Error("Failed to parse push config", "err", err)
			panic(err)
		}
		slog.Info(fmt.Sprintf("Loaded push config with %d entries", len(checkpointers)))
	}

	monerod, err := NewDaemon(*rpcUrl, httpClient, time.Second*30)
	if err != nil {
		slog.Error("Error creating monero client", "error", err)
		panic(err)
	}

	var check checkpoint.Checkpoint
	//TODO: get from DNS?

	if *checkpointStatePath != "" {
		stateData, err := os.ReadFile(*checkpointStatePath)
		if err != nil {
			slog.Error("Error reading state file", "error", err)
		} else {
			// we can continue - no state exists yet
			check, err = checkpoint.FromString(string(bytes.Split(stateData, []byte("\n"))[0]))
			if err != nil {
				slog.Error("Error parsing state file", "error", err)
			} else {
				slog.Info("Loaded checkpoint from state file", "height", check.Height, "id", check.Id)
			}
		}
	}

	type NotifyHeader struct {
		Height     uint64
		Id         types.Hash
		PreviousId types.Hash
	}

	tipNotifier := make(chan NotifyHeader, 10)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		tip, err := monerod.HeaderTip()
		if err != nil {
			slog.Error("Error getting tip", "error", err)
			panic(err)
		} else if err = monerod.Walk(tip, MaxInclusionDepth, nil); err != nil {
			slog.Error("Error getting walking tips", "error", err)
			panic(err)
		}
		slog.Info("New tip", "height", tip.Height, "id", tip.Id)

		var tipCheckpoint *BlockHeader
		if check.Id != types.ZeroHash {
			tipCheckpoint, err = monerod.HeaderById(check.Id)
			if err != nil {
				slog.Error("Error getting checkpoint tip", "error", err)
				panic(err)
			} else if err = monerod.Walk(tipCheckpoint, MaxInclusionDepth, nil); err != nil {
				slog.Error("Error getting checkpoint walking tips", "error", err)
				panic(err)
			}

			if ok, reason := monerod.HeaderIncluded(tip, tipCheckpoint); !ok {
				slog.Error("Tip does not include old checkpoint", "reason", reason)
				// we have reorg'd! this is not compatible and we have to wait till monero reorgs. keep crashing until we have a valid condition
				panic(reason)
			}
		}

		fallbackTimer := time.Tick(time.Second * 30)
		for {
			newTip, err := monerod.HeaderTip()
			if err != nil {
				slog.Error("Error getting tip", "error", err)
				panic(err)
			}
			if newTip.Id == tip.Id || tipCheckpoint == nil {
				// same
				continue
			}
			slog.Info("New tip", "height", newTip.Height, "id", newTip.Id)

			if ok, reason := monerod.HeaderIncluded(newTip, tip); !ok {
				slog.Error("New tip does not include old tip chain", "reason", reason)
				// we have reorg'd!
			}

			if tipCheckpoint != nil {
				if ok, reason := monerod.HeaderIncluded(newTip, tipCheckpoint); !ok {
					slog.Error("New tip does not include old checkpoint", "reason", reason)
					// we have reorg'd! this is not compatible and we have to wait till monero reorgs. keep crashing until we have a valid condition
					panic(reason)
				}
			}

			newCheckpoint, err := monerod.HeaderAtDepth(newTip, *checkpointDepth)
			if err != nil {
				slog.Error("Error getting new checkpoint depth", "error", err)
				panic(err)
			}

			//sanity check again
			if tipCheckpoint != nil {
				if ok, reason := monerod.HeaderIncluded(newCheckpoint, tipCheckpoint); !ok {
					slog.Error("New checkpoint does not include old checkpoint", "reason", reason)
					panic(reason)
				}
			}

			if tipCheckpoint == nil || newCheckpoint.Height > tipCheckpoint.Height {
				check = checkpoint.Checkpoint{
					Height: newCheckpoint.Height,
					Id:     newCheckpoint.Id,
				}

				tipCheckpoint = newCheckpoint

				slog.Info("New checkpoint", "height", newCheckpoint.Height, "id", newCheckpoint.Id)

				// sanity check: does monerod have the block?
				if _, err := monerod.FetchHeaderById(check.Id); err != nil {
					slog.Error("Error fetching checkpoint", "height", newCheckpoint.Height, "id", newCheckpoint.Id, "error", err)
					panic(err)
				}

				if *checkpointStatePath != "" {
					// atomically write new ones before pushing
					err = WriteFile(*checkpointStatePath, []byte(check.String()), 0777)
					if err != nil {
						slog.Error("Error writing checkpoint file", "error", err)
						panic(err)
					}
				}

				// Send updates to checkpointers
				// deadline for each
				for i, c := range checkpointers {
					if err := func() error {
						ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
						defer cancel()
						return c.Send(dialer, ctx, checkpoint.Checkpoints{check})
					}(); err != nil {
						slog.Error("Error sending checkpoint", "index", i, "error", err)
						// errors are fine
					}
				}
			}

			tip = newTip

			// wait
			select {
			case <-fallbackTimer:
			case h := <-tipNotifier:
				slog.Info("Got tip notification", "height", h.Height, "id", h.Id)
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		zmqClient := zmq.NewClient(*zmqAddr)
		for {
			err := zmqClient.Listen(context.Background(), zmq.Listeners{
				zmq.TopicMinimalChainMain: zmq.DecoderMinimalChainMain(func(chainMain *zmq.MinimalChainMain) {
					if len(chainMain.Ids) == 0 {
						return
					}
					root := NotifyHeader{
						Height:     chainMain.FirstHeight,
						Id:         chainMain.Ids[0],
						PreviousId: chainMain.FirstPrevID,
					}
					tipNotifier <- root

					if len(chainMain.Ids) > 1 {
						fmt.Printf("%+v\n", chainMain)
					}

					// not needed yet
					/*
						for _, id := range chainMain.Ids[1:] {
							b := NotifyHeader{
								Height:     root.Height - 1,
								Id:         id,
								PreviousId: root.Id,
							}
						}
					*/
				}),
			})
			if err != nil {
				slog.Error("Error listening zmq", "error", err)
			}
		}
	}()

	wg.Wait()

}
