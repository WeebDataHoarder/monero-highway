package monero

import (
	"bytes"
	"encoding/binary"
	"errors"

	"git.gammaspectra.live/P2Pool/consensus/v4/monero"
	"git.gammaspectra.live/P2Pool/consensus/v4/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v4/monero/transaction"
	"git.gammaspectra.live/P2Pool/consensus/v4/types"
	"git.gammaspectra.live/P2Pool/consensus/v4/utils"
)

type CoinbaseTransaction struct {
	Version uint8 `json:"version"`
	// UnlockTime would be here
	InputCount uint8 `json:"input_count"`
	InputType  uint8 `json:"input_type"`
	// UnlockTime re-arranged here to improve memory layout space
	UnlockTime uint64              `json:"unlock_time"`
	GenHeight  uint64              `json:"gen_height"`
	Outputs    transaction.Outputs `json:"outputs"`

	Extra types.Bytes `json:"extra"`

	ExtraBaseRCT uint8 `json:"extra_base_rct"`
}

// ExtraTags Returns a transaction extra decoded. This can err on corrupt blocks
func (c *CoinbaseTransaction) ExtraTags() (transaction.ExtraTags, error) {
	var tags transaction.ExtraTags
	err := tags.UnmarshalBinary(c.Extra)
	if err != nil {
		return nil, err
	}
	return tags, nil
}

func (c *CoinbaseTransaction) TotalReward() (reward uint64) {
	for _, o := range c.Outputs {
		reward += o.Reward
	}
	return reward
}

func (c *CoinbaseTransaction) UnmarshalBinary(data []byte) error {
	reader := bytes.NewReader(data)
	err := c.FromReader(reader)
	if err != nil {
		return err
	}
	if reader.Len() > 0 {
		return errors.New("leftover bytes in reader")
	}
	return nil
}

func (c *CoinbaseTransaction) FromReader(reader utils.ReaderAndByteReader) (err error) {
	var (
		txExtraSize uint64
	)

	if c.Version, err = reader.ReadByte(); err != nil {
		return err
	}

	if c.Version != 2 {
		return errors.New("version not supported")
	}

	if c.UnlockTime, err = utils.ReadCanonicalUvarint(reader); err != nil {
		return err
	}

	if c.InputCount, err = reader.ReadByte(); err != nil {
		return err
	}

	if c.InputCount != 1 {
		return errors.New("invalid input count")
	}

	if c.InputType, err = reader.ReadByte(); err != nil {
		return err
	}

	if c.InputType != transaction.TxInGen {
		return errors.New("invalid coinbase input type")
	}

	if c.GenHeight, err = utils.ReadCanonicalUvarint(reader); err != nil {
		return err
	}

	if c.UnlockTime != (c.GenHeight + monero.MinerRewardUnlockTime) {
		return errors.New("invalid unlock time")
	}

	if err = c.Outputs.FromReader(reader); err != nil {
		return err
	}

	if txExtraSize, err = utils.ReadCanonicalUvarint(reader); err != nil {
		return err
	}

	limitReader := utils.LimitByteReader(reader, int64(txExtraSize))

	_, err = utils.ReadFullProgressive(limitReader, &c.Extra, int(txExtraSize))
	if err != nil {
		return err
	}

	if limitReader.Left() > 0 {
		return errors.New("bytes leftover in extra data")
	}

	if err = binary.Read(reader, binary.LittleEndian, &c.ExtraBaseRCT); err != nil {
		return err
	}

	if c.ExtraBaseRCT != 0 {
		return errors.New("invalid extra base RCT")
	}

	return nil
}

func (c *CoinbaseTransaction) BufferLength() int {
	return 1 +
		utils.UVarInt64Size(c.UnlockTime) +
		1 + 1 +
		utils.UVarInt64Size(c.GenHeight) +
		c.Outputs.BufferLength() +
		utils.UVarInt64Size(len(c.Extra)) + len(c.Extra) + 1
}

func (c *CoinbaseTransaction) MarshalBinary() ([]byte, error) {
	return c.AppendBinary(make([]byte, 0, c.BufferLength()))
}

func (c *CoinbaseTransaction) AppendBinary(preAllocatedBuf []byte) ([]byte, error) {
	buf := preAllocatedBuf

	buf = append(buf, c.Version)
	buf = binary.AppendUvarint(buf, c.UnlockTime)
	buf = append(buf, c.InputCount)
	buf = append(buf, c.InputType)
	buf = binary.AppendUvarint(buf, c.GenHeight)

	buf, _ = c.Outputs.AppendBinary(buf)

	buf = binary.AppendUvarint(buf, uint64(len(c.Extra)))
	buf = append(buf, c.Extra...)
	buf = append(buf, c.ExtraBaseRCT)

	return buf, nil
}

func (c *CoinbaseTransaction) OutputsBlob() ([]byte, error) {
	return c.Outputs.MarshalBinary()
}

var baseRCTZeroHash = crypto.PooledKeccak256([]byte{0})

func (c *CoinbaseTransaction) CalculateId() (hash types.Hash) {

	txBytes, _ := c.AppendBinary(make([]byte, 0, c.BufferLength()))

	hasher := crypto.GetKeccak256Hasher()
	defer crypto.PutKeccak256Hasher(hasher)

	// coinbase id, base RCT hash, prunable RCT hash
	var txHashingBlob [3 * types.HashSize]byte

	// remove base RCT
	_, _ = hasher.Write(txBytes[:len(txBytes)-1])
	crypto.HashFastSum(hasher, txHashingBlob[:])

	if c.ExtraBaseRCT == 0 {
		// Base RCT, single 0 byte in miner tx
		copy(txHashingBlob[1*types.HashSize:], baseRCTZeroHash[:])
	} else {
		// fallback, but should never be hit
		hasher.Reset()
		_, _ = hasher.Write([]byte{c.ExtraBaseRCT})
		crypto.HashFastSum(hasher, txHashingBlob[1*types.HashSize:])
	}

	// Prunable RCT, empty in miner tx
	//copy(txHashingBlob[2*types.HashSize:], types.ZeroHash[:])

	hasher.Reset()
	_, _ = hasher.Write(txHashingBlob[:])
	crypto.HashFastSum(hasher, hash[:])

	return hash
}
