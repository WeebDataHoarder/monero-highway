package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"git.gammaspectra.live/P2Pool/consensus/v4/monero/client/rpc"
	"git.gammaspectra.live/P2Pool/consensus/v4/monero/client/rpc/daemon"
	"git.gammaspectra.live/P2Pool/consensus/v4/types"
)

type Daemon struct {
	rpc     *rpc.Client
	daemon  *daemon.Client
	timeout time.Duration

	lock   sync.RWMutex
	blocks map[types.Hash]*BlockHeader

	restricted bool
	rateLimit  *time.Ticker
}

type BlockHeader struct {
	Height     uint64
	Id         types.Hash `json:"id"`
	PreviousId types.Hash `json:"previous_id"`

	Difficulty           types.Difficulty `json:"difficulty"`
	CumulativeDifficulty types.Difficulty `json:"cumulative_difficulty"`
}

func NewDaemon(rpcUrl string, client *http.Client, timeout time.Duration) (*Daemon, error) {
	rpcServer, err := rpc.NewClient(rpcUrl, rpc.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	moneroDaemon := daemon.NewClient(rpcServer)

	d := &Daemon{
		timeout:    timeout,
		rpc:        rpcServer,
		daemon:     moneroDaemon,
		blocks:     make(map[types.Hash]*BlockHeader),
		restricted: true,
		// allow 1000 requests per second
		rateLimit: time.NewTicker(time.Second / 1000),
	}

	return d, nil
}

func (d *Daemon) headerById(id types.Hash) *BlockHeader {
	d.lock.RLock()
	defer d.lock.RUnlock()
	return d.blocks[id]
}

func headerFromRPC(h daemon.BlockHeader) *BlockHeader {
	return &BlockHeader{
		Height:               h.Height,
		Id:                   h.Hash,
		PreviousId:           h.PrevHash,
		Difficulty:           types.NewDifficulty(h.Difficulty, h.DifficultyTop64),
		CumulativeDifficulty: types.NewDifficulty(h.CumulativeDifficulty, h.CumulativeDifficultyTop64),
	}
}

const MaxInclusionDepth = 720

// HeaderIncluded Walks a chain backwards via previous id hashes to find if root is part of the chain tip is on
func (d *Daemon) HeaderIncluded(tip, root *BlockHeader) (ok bool, reason error) {
	if tip == nil || root == nil {
		return false, errors.New("tip or root is nil")
	}

	if root.Height > tip.Height {
		// a root at higher height cannot be included in tip
		return false, errors.New("root height is greater than tip height")
	} else if root.Height == tip.Height {
		if root.Id == tip.Id {
			// tip is included, it's the same
			return true, nil
		}
		// a root at same height with different id cannot be included in tip
		return false, errors.New("root height is equal to tip height but ids are different")
	}

	// add a sanity limit
	inclusionDepth := min(tip.Height-root.Height, MaxInclusionDepth)

	var found bool
	err := d.Walk(tip, inclusionDepth, func(h *BlockHeader) (ok bool) {
		// found root
		if h.Height == root.Height && h.Id == root.Id {
			// tip is included
			found = true
			return false
		}
		// continue
		return true
	})
	if err != nil {
		return false, err
	}
	if found {
		return true, nil
	}

	return false, errors.New("inclusion depth exceeds limits or reached genesis block")
}

// Walk Walks a chain backwards via previous id hashes. Limit is in depths from tip
func (d *Daemon) Walk(tip *BlockHeader, limit uint64, each func(h *BlockHeader) (ok bool)) (err error) {
	if tip == nil {
		return errors.New("tip is nil")
	}

	// add a sanity limit
	inclusionDepth := limit

	for tip.Height > 0 && inclusionDepth > 0 {
		parent, err := d.HeaderById(tip.PreviousId)
		if err != nil {
			return fmt.Errorf("while obtaining block %s @ %d: %w", tip.PreviousId, tip.Height-1, err)
		}

		if parent.Height != tip.Height-1 {
			// ??? defensive check
			return errors.New("parent height mismatch")
		}

		if each != nil && !each(parent) {
			// we are done
			break
		}
		inclusionDepth--
		tip = parent
	}

	return nil
}

// HeaderAtDepth Fetches a header at a specific depth from tip
func (d *Daemon) HeaderAtDepth(tip *BlockHeader, depth uint64) (deepHeader *BlockHeader, err error) {
	if depth == 0 {
		return tip, nil
	}
	err = d.Walk(tip, depth, func(h *BlockHeader) (ok bool) {
		if h.Height == tip.Height-depth {
			deepHeader = h
			return false
		}
		return true
	})
	return deepHeader, err
}

func (d *Daemon) HeaderTip() (*BlockHeader, error) {
	<-d.rateLimit.C

	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()

	r, err := d.daemon.GetLastBlockHeader(ctx)
	if err != nil {
		return nil, err
	}

	if r.BlockHeader.Hash == types.ZeroHash {
		return nil, fmt.Errorf("expected block header to have valid hash")
	}

	h := headerFromRPC(r.BlockHeader)

	d.lock.Lock()
	defer d.lock.Unlock()
	d.blocks[h.Id] = h

	return h, nil
}

func (d *Daemon) HeaderById(id types.Hash) (*BlockHeader, error) {
	if h := d.headerById(id); h != nil {
		return h, nil
	}
	return d.FetchHeaderById(id)
}

func (d *Daemon) FetchHeaderById(id types.Hash) (*BlockHeader, error) {
	<-d.rateLimit.C
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()

	r, err := d.daemon.GetBlockHeaderByHash(ctx, []types.Hash{id})
	if err != nil {
		return nil, err
	}

	if len(r.BlockHeaders) != 1 {
		return nil, fmt.Errorf("expected 1 block header")
	}

	if r.BlockHeaders[0].Hash != id {
		return nil, fmt.Errorf("expected block header to have hash %x, got %x", id.Slice(), r.BlockHeaders[0].Hash.Slice())
	}

	h := headerFromRPC(r.BlockHeaders[0])

	d.lock.Lock()
	defer d.lock.Unlock()
	d.blocks[id] = h

	return h, nil
}

func (d *Daemon) HeadersById(ids ...types.Hash) (result []*BlockHeader, err error) {
	result = make([]*BlockHeader, len(ids))
	// first fetch all we can!
	if found := func() (found int) {
		d.lock.RLock()
		defer d.lock.RUnlock()

		for i, id := range ids {
			if h, ok := d.blocks[id]; ok {
				result[i] = h
				found++
			}
		}
		return found
	}(); found == len(ids) {
		return result, nil
	} else {
		request := make([]types.Hash, 0, len(ids)-found)

		for i := range result {
			if result[i] == nil {
				request = append(request, ids[i])
			}
		}

		if len(request) > 1000 && d.restricted {
			return nil, fmt.Errorf("restricted: at most %d blocks can be requested, got %d", 1000, len(request))
		}

		<-d.rateLimit.C
		ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
		defer cancel()

		r, err := d.daemon.GetBlockHeaderByHash(ctx, request)
		if err != nil {
			return result, err
		}

		if len(r.BlockHeaders) != len(request) {
			return result, fmt.Errorf("wrong block header count")
		}

		for _, h := range r.BlockHeaders {
			if i := slices.Index(ids, h.Hash); i == -1 {
				return result, fmt.Errorf("mismatched block id: not found")
			} else if result[i] != nil {
				return result, fmt.Errorf("mismatched block id: already exists")
			} else {
				result[i] = headerFromRPC(h)
			}
		}

		// sanity check, any nil blocks?
		// also store them back

		d.lock.Lock()
		defer d.lock.Unlock()
		for _, h := range result {
			if h == nil {
				return result, fmt.Errorf("wrong block header result")
			} else {
				d.blocks[h.Id] = h
			}
		}
		return result, nil
	}
}
