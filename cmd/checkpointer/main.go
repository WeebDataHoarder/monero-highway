package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"git.gammaspectra.live/P2Pool/consensus/v4/monero/client/zmq"
	"git.gammaspectra.live/P2Pool/consensus/v4/types"
	"git.gammaspectra.live/P2Pool/monero-highway/internal/highway/checkpoint"
)

func main() {
	rpcUrl := flag.String("rpc", "http://127.0.0.1:18081", "Monero RPC server URL. Can be restricted")
	zmqAddr := flag.String("zmq", "tcp://127.0.0.1:18083", "Monero ZMQ-PUB server address")
	statePath := flag.String("state", "checkpoints.txt", "File where to save checkpoint state. Directory where it is emplaced must be writable and on same mount")

	checkpointDepth := flag.Uint64("checkpoint-depth", 2, "Depth from tip to place checkpoints at. Depth of 2, means tip height of 100 will checkpoint 98")

	flag.Parse()

	httpClient := &http.Client{
		Transport: &http.Transport{},
		Timeout:   time.Second * 30,
	}

	monerod, err := NewDaemon(*rpcUrl, httpClient, time.Second*30)
	if err != nil {
		slog.Error("Error creating monero client", "error", err)
		panic(err)
	}

	var check checkpoint.Checkpoint
	//TODO: get from DNS?

	if *statePath != "" {
		stateData, err := os.ReadFile(*statePath)
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
					// we have reorg'd!
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
				if *statePath != "" {
					// atomically write new ones before pushing
					err = WriteFile(*statePath, []byte(check.String()), 0777)
					if err != nil {
						slog.Error("Error writing checkpoint file", "error", err)
						panic(err)
					}
				}

				//TODO: submit updates
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
