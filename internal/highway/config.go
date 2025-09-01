package highway

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"

	"git.gammaspectra.live/P2Pool/consensus/v4/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v4/monero/randomx"
	"git.gammaspectra.live/P2Pool/consensus/v4/types"
	"golang.org/x/net/proxy"
)

type Configuration struct {
	// Bind Address to bind to
	Bind string `yaml:"bind"`

	// Peers known list of peer addresses to connect to
	// Can be IP:PORT or hosts
	Peers []string `yaml:"peers"`

	// Proxy Target proxy URL to use for all outgoing connections
	// Includes peering, RPC and ZMQ
	// Default none
	// Example TOR: socks5://127.0.0.1:9050
	Proxy string `yaml:"socks5"`

	// Monero List of monero servers this is connected to
	Monero []*MoneroServerConfig `yaml:"monero"`

	// State Options related to sync state
	// Defaults to DefaultStateConfig
	// This configuration must match across all participants
	State StateConfig `yaml:"state"`

	// FixedCheckpoints Checkpoint to add to the records regardless
	// Could be manual ones, or old ones that need to be kept
	// Values must be sorted descending on height
	FixedCheckpoints Checkpoints `yaml:"fixed-checkpoints"`
}

func (c Configuration) Dialer() (proxy.Dialer, error) {
	d := &net.Dialer{
		Timeout:       30 * time.Second,
		KeepAlive:     15 * time.Second,
		FallbackDelay: 500 * time.Millisecond,
	}

	if c.Proxy != "" {
		uri, err := url.Parse(c.Proxy)
		if err != nil {
			return nil, err
		}

		return proxy.FromURL(uri, d)
	}
	return d, nil
}

func (c Configuration) Verify() error {
	if err := c.State.Verify(); err != nil {
		return fmt.Errorf("state config verification failed: %w", err)
	}
	for _, m := range c.Monero {
		if err := m.Verify(); err != nil {
			return fmt.Errorf("monero config verification failed: %w", err)
		}
	}
	if err := c.FixedCheckpoints.Validate(); err != nil {
		return fmt.Errorf("fixed-checkpoints verification failed: %w", err)
	}
	if _, err := c.Dialer(); err != nil {
		return fmt.Errorf("proxy dialer config verification failed: %w", err)
	}
	return nil
}

var DefaultStateConfig = StateConfig{
	// This key will be set by participating nodes
	PeerKey: types.ZeroHash,
	// Defaults to 2048 * 2 + 64 * 2, for having two RandomX epochs fully plus the lag and a bit extra (one more epoch
	KeepDepth:            randomx.SeedHashEpochLag*2 + randomx.SeedHashEpochBlocks + randomx.SeedHashEpochBlocks,
	CheckpointDepth:      2,
	CheckpointSeparation: 1,
	CheckpointKeepCount:  10,

	// Keep the last two RandomX epochs as checkpoints
	CheckpointLastEpochs: 2,
}

type StateConfig struct {
	// PeerKey A random value to verify membership of the state, in addition of other keys
	PeerKey types.Hash `yaml:"key"`

	// KeepDepth Number of heights from highest known processed tip in the canonical agreed chain across checkpoint nodes that are kept for state lookups
	// This includes alt blocks
	KeepDepth uint64 `yaml:"keep-depth"`

	// CheckpointDepth Number of heights from highest known tip in the canonical agreed chain which will decide to checkpoint or not
	// Example 1: CheckpointDepth = 2, tip is at 1000, and a checkpoint is to be placed, it'd be selected across valid blocks at height 998
	// Example 2: CheckpointDepth = 0, tip is at 1000, and a checkpoint is to be placed, it'd be selected across valid blocks at height 1000
	CheckpointDepth uint64 `yaml:"checkpoint-depth"`

	// CheckpointSeparation Separation between checkpoints to place eligible checkpoints at
	// If a checkpoint was placed at 1000, the next checkpoint could be placed at height 1001 + CheckpointSeparation
	// Example 1: CheckpointSeparation = 1, checkpoints would be placed at 1000, 1002, 1004, 1006
	// Example 2: CheckpointSeparation = 2, checkpoints would be placed at 1000, 1003, 1006, 1009
	// Example 3: CheckpointSeparation = 0, checkpoints would be placed at 1000, 1001, 1002, 1003
	CheckpointSeparation uint64 `yaml:"checkpoint-separation"`

	// NOTE: calculation of depth and separation is done from the RandomX Seed height, randomx.SeedHeight
	// Example: CheckpointDepth = 2, CheckpointSeparation = 1
	// Eligibility: candidate.height+CheckpointDepth == tip.height && (candidate.height-randomx.SeedHeight(candidate.height))%(CheckpointSeparation+1) == 0
	// See CheckpointEligible method

	// CheckpointKeepCount Count of checkpoints past most recent to keep, not including CheckpointLastEpochs
	// Effectively FIFO
	// Example 1: CheckpointKeepCount = 0, only 1000 would be kept and be always increasing
	// Example 2: CheckpointKeepCount = 2, most recent + 2 more recent checkpoints would be kept
	CheckpointKeepCount uint64 `yaml:"checkpoint-keep-count"`

	// CheckpointLastEpochs Keep one checkpoint for the most recent randomx.SeedHeight
	// KeepDepth Must be greater or equal than these epochs
	// Example 1: CheckpointLastEpochs = 0, no extra checkpoints kept
	// Example 2: CheckpointLastEpochs = 1, randomx.SeedHeight(candidate.height) would be kept
	// Example 2: CheckpointLastEpochs = 2, randomx.SeedHeight(candidate.height) and randomx.SeedHeight(randomx.SeedHeight(candidate.height)) would be kept
	CheckpointLastEpochs uint64 `yaml:"checkpoint-last-epochs"`
}

func (sc StateConfig) TotalCheckpointCount() uint64 {
	return sc.CheckpointKeepCount + sc.CheckpointLastEpochs
}

func (sc StateConfig) CheckpointEligible(candidate, tip uint64) bool {
	return candidate+sc.CheckpointKeepCount == tip && (candidate-randomx.SeedHeight(candidate))%(sc.CheckpointSeparation+1) == 0
}

// Id Returns the binary hashed version of the state to be used for consensus
func (sc StateConfig) Id() (id types.Hash) {
	hasher := crypto.GetKeccak256Hasher()
	defer crypto.PutKeccak256Hasher(hasher)
	buf, err := sc.MarshalBinary()
	if err != nil {
		panic(err)
	}
	_, _ = hasher.Write(buf)
	crypto.HashFastSum(hasher, id[:])
	return id
}

func (sc StateConfig) Verify() error {
	if sc.KeepDepth < sc.CheckpointLastEpochs*randomx.SeedHashEpochBlocks+randomx.SeedHashEpochLag {
		return errors.New("keep-depth too low")
	}
	if sc.KeepDepth < (sc.CheckpointDepth + sc.CheckpointSeparation + 1*sc.CheckpointKeepCount) {
		return errors.New("keep-depth too low")
	}
	return nil
}

func (sc StateConfig) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 8*5+types.HashSize)
	n, err := binary.Encode(buf, binary.LittleEndian, sc)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

type MoneroServerConfig struct {
	// RPC Address of monerod RPC
	// Example http://127.0.0.1:18081
	// Required
	RPC string `yaml:"rpc"`

	// ZMQ Address of monerod ZMQ pub
	// Example tcp://127.0.0.1:18083
	// Optional, if not specified no notifications will be provided
	ZMQ string `yaml:"zmq"`

	// P2P Address, remote that anyone can connect to
	// Optional
	P2P string `yaml:"p2p"`

	// Features Options selected
	// Optional, defaults to DefaultMoneroServerOptions
	Options *MoneroServerOptions `yaml:"options"`

	// Features Custom features supported
	// Optional
	Features MoneroServerFeatures `yaml:"features"`
}

func (mc *MoneroServerConfig) Verify() error {
	if mc.Options == nil {
		// copy
		opts := DefaultMoneroServerOptions
		mc.Options = &opts
	}

	if (mc.Options.SubmitBlocks || mc.Options.SubmitTransactions) && mc.RPC == "" {
		return errors.New("submit-blocks or submit-transactions requires rpc")
	} else if (mc.Options.GatherBlocks || mc.Options.GatherTransactions) && mc.ZMQ == "" {
		return errors.New("gather-blocks or gather-transactions requires zmq")
	}

	return nil
}

var DefaultMoneroServerOptions = MoneroServerOptions{
	GatherBlocks: true,

	// Defaults to false. Enable this on nodes that can sustain higher RPC calls
	// Transaction ids are still gathered
	GatherTransactions: false,

	SubmitBlocks: true,

	// Defaults to false as it's a high bandwidth requirement
	SubmitTransactions: false,

	// Raise rate limit if you gather or submit transactions
	RateLimit: 100,
}

type MoneroServerOptions struct {
	// GatherBlocks Use this node as a source to gather blocks
	// Requires ZMQ and RPC
	GatherBlocks bool `yaml:"gather-blocks"`

	// GatherTransactions Use this node as a source to gather transactions
	// Requires ZMQ and RPC
	// Even if disabled transactions ids may be gathered
	GatherTransactions bool `yaml:"gather-transactions"`

	// SubmitBlocks Attempt to submit unknown transactions to this node via RPC
	SubmitTransactions bool `yaml:"submit-transactions"`

	// SubmitBlocks Attempt to submit unknown blocks to this node via RPC
	SubmitBlocks bool `yaml:"submit-blocks"`

	// RateLimit Number of RPC calls that can be done per second
	RateLimit uint64 `yaml:"rate-limit"`
}

type MoneroServerFeatures struct {
	// RPCSubmitOldBlocks Allow submitting old orphans or alt blocks via submit_block RPC.
	// custom patch required
	// TODO: otherwise submit via P2P Fluffy blocks?
	RPCSubmitOldBlocks bool `yaml:"rpc-submit-old-blocks"`

	// ZMQAlternateBlockNotify Receive alternate block notifications via ZMQ
	// custom patch required
	// otherwise will poll RPC /get_alt_blocks_hashes
	ZMQAlternateBlockNotify bool `yaml:"zmq-alternate-block-notify"`
}
