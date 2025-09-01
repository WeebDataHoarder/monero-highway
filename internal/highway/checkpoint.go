package highway

import (
	"errors"
	"fmt"
	"slices"

	"git.gammaspectra.live/P2Pool/consensus/v4/types"
)

type Checkpoint struct {
	Height uint64     `yaml:"height"`
	Id     types.Hash `yaml:"id" json:"id"`
}

func (c Checkpoint) String() string {
	return fmt.Sprintf("%d:%x", c.Height, c.Id.Slice())
}

type Checkpoints []Checkpoint

func (c Checkpoints) Validate() error {
	if !c.sorted() {
		return errors.New("checkpoints must be sorted")
	}
	if len(c) == 0 {
		return nil
	}
	var lastHeight uint64
	for i, checkpoint := range c {
		if i > 0 && lastHeight == checkpoint.Height {
			return errors.New("checkpoints must not be the same height as each other")
		}
		lastHeight = checkpoint.Height

		if checkpoint.Id == types.ZeroHash {
			return errors.New("checkpoints must have an id")
		}
	}
	return nil
}

func (c Checkpoints) Index(other Checkpoint) int {
	return slices.Index(c, other)
}

func (c Checkpoints) IndexHash(id types.Hash) int {
	return slices.IndexFunc(c, func(checkpoint Checkpoint) bool {
		return checkpoint.Id == id
	})
}

func (c Checkpoints) IndexHeight(height uint64) int {
	return slices.IndexFunc(c, func(checkpoint Checkpoint) bool {
		return checkpoint.Height == height
	})
}

func (c Checkpoints) sorted() bool {
	// sorted descending
	return slices.IsSortedFunc(c, func(a, b Checkpoint) int {
		return int(b.Height) - int(a.Height)
	})
}

func (c Checkpoints) Sort() {
	// sorted descending
	slices.SortFunc(c, func(a, b Checkpoint) int {
		return int(b.Height) - int(a.Height)
	})
}
