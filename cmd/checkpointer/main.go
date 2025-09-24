package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"slices"
	"time"

	"git.gammaspectra.live/P2Pool/consensus/v4/monero/client/zmq"
	"git.gammaspectra.live/P2Pool/consensus/v4/types"
	"git.gammaspectra.live/P2Pool/monero-highway/internal/highway/checkpoint"
	"github.com/goccy/go-yaml"
	"golang.org/x/sync/errgroup"
)

type MoneroCheckpoints struct {
	Hashlines []MoneroCheckpoint `json:"hashlines,omitempty"`
}

type MoneroCheckpoint struct {
	Hash   types.Hash `json:"hash"`
	Height uint64     `json:"height"`
}

func main() {
	rpcUrl := flag.String("rpc", "http://127.0.0.1:18081", "Monero RPC server URL. Can be restricted")
	zmqAddr := flag.String("zmq", "tcp://127.0.0.1:18083", "Monero ZMQ-PUB server address")

	doLoop := flag.Bool("loop", false, "By default the program will bail out when a sanity check fails or miscondition happens. Enable this to make it loop instead from scratch")
	pushConfigPath := flag.String("push-config", "", "Path to YAML file to push records")
	checkpointStatePath := flag.String("checkpoint-state", "checkpoints.json", "File where to save checkpoints.json state. Directory where it is emplaced must be writable and on same mount. Same format as used in Monero, point this to the .bitmonero folder or .bitmonero/testnet for loading the checkpoints faster.")
	checkpointDepth := flag.Uint64("checkpoint-depth", 2, "Depth from tip to place checkpoints at. Depth of 2, means tip height of 100 will checkpoint 98")
	checkpointInterval := flag.Duration("checkpoint-interval", 0, "Interval when checkpoints will be set. Default zero, checkpoint instantly. Recommended: 5m")

	flag.Parse()

	for {
		func() {
			if *doLoop {
				defer func() {
					if r := recover(); r != nil {
						slog.Error(fmt.Sprintf("panic: %v\n", r))
						// prevent fast crashes
						time.Sleep(5 * time.Second)
						slog.Info("recovered, starting anew\n")
					}
				}()
			}

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
					var checkpointState MoneroCheckpoints
					// we can continue - no state exists yet
					err = json.Unmarshal(stateData, &checkpointState)
					if err != nil {
						slog.Error("Error parsing state file", "error", err)
					} else if len(checkpointState.Hashlines) > 0 {
						// DESC
						slices.SortFunc(checkpointState.Hashlines, func(a, b MoneroCheckpoint) int {
							return int(b.Height) - int(a.Height)
						})
						// take highest
						check.Height = checkpointState.Hashlines[0].Height
						check.Id = checkpointState.Hashlines[0].Hash

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

			closeCtx, closeCancel := context.WithCancel(context.Background())
			defer closeCancel()

			var wg errgroup.Group
			wg.Go(func() error {
				defer closeCancel()
				var intervalTicker <-chan time.Time
				if *checkpointInterval <= 0 {
					// special case
					channel := make(chan time.Time)
					close(channel)
					intervalTicker = channel
				} else {
					if *checkpointInterval/20 > 0 {
						channel := make(chan time.Time)
						go func() {
							for {
								// add 5% fuzz interval over expected interval
								time.Sleep(*checkpointInterval + time.Duration(rand.Int64N(int64(*checkpointInterval/20))))
								channel <- time.Now()
							}
						}()
						intervalTicker = channel
					} else {
						intervalTicker = time.Tick(*checkpointInterval)
					}
				}

				tip, err := monerod.HeaderTip()
				if err != nil {
					slog.Error("Error getting tip", "error", err)
					return err
				} else if err = monerod.Walk(tip, MaxInclusionDepth, nil); err != nil {
					slog.Error("Error getting walking tips", "error", err)
					return err
				}
				slog.Info("Initial tip", "height", tip.Height, "id", tip.Id)

				var tipCheckpoint *BlockHeader
				if check.Id != types.ZeroHash {
					tipCheckpoint, err = monerod.HeaderById(check.Id)
					if err != nil {
						slog.Error("Error getting checkpoint tip", "error", err)
						return err
					} else if err = monerod.Walk(tipCheckpoint, MaxInclusionDepth, nil); err != nil {
						slog.Error("Error getting checkpoint walking tips", "error", err)
						return err
					}

					if ok, reason := monerod.HeaderIncluded(tip, tipCheckpoint); !ok {
						slog.Error("Tip does not include old checkpoint", "reason", reason)
						// we have reorg'd! this is not compatible and we have to wait till monero reorgs. keep crashing until we have a valid condition

						return fmt.Errorf("tip does not include old checkpoint: %s", reason)
					}
				}

				fallbackTimer := time.Tick(time.Second * 30)
				var checkedTicker bool
				for {
					newTip, err := monerod.HeaderTip()
					if err != nil {
						slog.Error("Error getting tip", "error", err)
						return err
					}

					if newTip.Id == tip.Id && !checkedTicker {
						// wait
						checkedTicker = false
						select {
						case <-fallbackTimer:
						case <-intervalTicker:
							checkedTicker = true
						case h := <-tipNotifier:
							slog.Info("Got tip notification", "height", h.Height, "id", h.Id)
						}

						// same
						continue
					}
					slog.Info("Tip", "height", newTip.Height, "id", newTip.Id)

					if ok, reason := monerod.HeaderIncluded(newTip, tip); !ok {
						slog.Error("New tip does not include old tip chain", "reason", reason)
						// we have reorg'd!
					}

					if !checkedTicker {
						select {
						case <-intervalTicker:
						default:

							tip = newTip
							slog.Info("Checkpoint interval not reached, delaying")
							// sleep again
							continue
						}
					}

					if tipCheckpoint != nil {
						if ok, reason := monerod.HeaderIncluded(newTip, tipCheckpoint); !ok {
							slog.Error("New tip does not include old checkpoint", "reason", reason)
							// we have reorg'd! this is not compatible and we have to wait till monero reorgs. keep crashing until we have a valid condition

							return fmt.Errorf("tip does not include old checkpoint: %s", reason)
						}
					}

					newCheckpoint, err := monerod.HeaderAtDepth(newTip, *checkpointDepth)
					if err != nil {
						slog.Error("Error getting new checkpoint depth", "error", err)
						return err
					}

					//sanity check again
					if tipCheckpoint != nil {
						if ok, reason := monerod.HeaderIncluded(newCheckpoint, tipCheckpoint); !ok {
							slog.Error("New checkpoint does not include old checkpoint", "reason", reason)

							return fmt.Errorf("checkpoint does not include old checkpoint: %s", reason)
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

							return err
						}

						if *checkpointStatePath != "" {
							checkpointsState := MoneroCheckpoints{
								Hashlines: []MoneroCheckpoint{
									{
										Height: check.Height,
										Hash:   check.Id,
									},
								},
							}
							blob, err := json.MarshalIndent(&checkpointsState, "", "    ")
							if err != nil {
								slog.Error("Error marshaling checkpoint state", "error", err)
							}

							// atomically write new ones before pushing
							err = WriteFile(*checkpointStatePath, blob, 0777)
							if err != nil {
								slog.Error("Error writing checkpoint file", "error", err)

								return err
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
								// errors are fine here
							}
						}
					}

					tip = newTip
					checkedTicker = false
				}

			})

			zmqClient := zmq.NewClient(*zmqAddr)

			wg.Go(func() error {
				defer closeCancel()
				for {

					select {
					case <-closeCtx.Done():
						return nil
					default:
					}
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
							select {
							case tipNotifier <- root:
							case <-closeCtx.Done():
								return
							}
						}),
					})
					if err != nil {
						slog.Error("Error listening zmq", "error", err)
					}
				}
			})

			if err := wg.Wait(); err != nil {
				panic(err)
			}

			_ = zmqClient.Close()
		}()

	}

}
