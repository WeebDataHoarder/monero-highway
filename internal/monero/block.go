package monero

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"git.gammaspectra.live/P2Pool/consensus/v4/monero"
	"git.gammaspectra.live/P2Pool/consensus/v4/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v4/types"
	"git.gammaspectra.live/P2Pool/consensus/v4/utils"
)

const MaxTransactionCount = uint64(math.MaxUint64) / types.HashSize

type Block struct {
	MajorVersion uint8  `json:"major_version"`
	MinorVersion uint64 `json:"minor_version"`
	// Nonce re-arranged here to improve memory layout space
	Nonce uint32 `json:"nonce"`

	Timestamp  uint64     `json:"timestamp"`
	PreviousId types.Hash `json:"previous_id"`
	//Nonce would be here

	Coinbase CoinbaseTransaction `json:"coinbase"`

	Transactions []types.Hash `json:"transactions,omitempty"`
}

type Header struct {
	MajorVersion uint8  `json:"major_version"`
	MinorVersion uint64 `json:"minor_version"`
	// Nonce re-arranged here to improve memory layout space
	Nonce uint32 `json:"nonce"`

	Timestamp  uint64     `json:"timestamp"`
	PreviousId types.Hash `json:"previous_id"`
	Height     uint64     `json:"height"`
	//Nonce would be here
	Reward     uint64           `json:"reward"`
	Difficulty types.Difficulty `json:"difficulty"`
	Id         types.Hash       `json:"id"`
}

func (b *Block) MarshalBinary() (buf []byte, err error) {
	return b.AppendBinary(make([]byte, 0, b.BufferLength()))
}

func (b *Block) BufferLength() int {
	return utils.UVarInt64Size(b.MajorVersion) +
		utils.UVarInt64Size(b.MinorVersion) +
		utils.UVarInt64Size(b.Timestamp) +
		types.HashSize +
		4 +
		b.Coinbase.BufferLength() +
		utils.UVarInt64Size(len(b.Transactions)) + types.HashSize*len(b.Transactions)
}

func (b *Block) AppendBinary(preAllocatedBuf []byte) (buf []byte, err error) {
	buf = preAllocatedBuf

	if b.MajorVersion > monero.HardForkSupportedVersion {
		return nil, fmt.Errorf("unsupported version %d", b.MajorVersion)
	}

	if b.MinorVersion < uint64(b.MajorVersion) {
		return nil, fmt.Errorf("minor version %d smaller than major %d", b.MinorVersion, b.MajorVersion)
	}

	buf = binary.AppendUvarint(buf, uint64(b.MajorVersion))
	buf = binary.AppendUvarint(buf, b.MinorVersion)

	buf = binary.AppendUvarint(buf, b.Timestamp)
	buf = append(buf, b.PreviousId[:]...)
	buf = binary.LittleEndian.AppendUint32(buf, b.Nonce)

	if buf, err = b.Coinbase.AppendBinary(buf); err != nil {
		return nil, err
	}

	buf = binary.AppendUvarint(buf, uint64(len(b.Transactions)))
	for _, txId := range b.Transactions {
		buf = append(buf, txId[:]...)
	}

	return buf, nil
}

func (b *Block) UnmarshalBinary(data []byte) error {
	reader := bytes.NewReader(data)
	err := b.FromReader(reader)
	if err != nil {
		return err
	}
	if reader.Len() > 0 {
		return errors.New("leftover bytes in reader")
	}
	return nil
}

func (b *Block) FromReader(reader utils.ReaderAndByteReader) (err error) {
	var (
		txCount         uint64
		transactionHash types.Hash
	)

	if b.MajorVersion, err = reader.ReadByte(); err != nil {
		return err
	}

	if b.MajorVersion > monero.HardForkSupportedVersion {
		return fmt.Errorf("unsupported version %d", b.MajorVersion)
	}

	if b.MinorVersion, err = utils.ReadCanonicalUvarint(reader); err != nil {
		return err
	}

	if b.MinorVersion < uint64(b.MajorVersion) {
		return fmt.Errorf("minor version %d smaller than major version %d", b.MinorVersion, b.MajorVersion)
	}

	if b.Timestamp, err = utils.ReadCanonicalUvarint(reader); err != nil {
		return err
	}

	if _, err = io.ReadFull(reader, b.PreviousId[:]); err != nil {
		return err
	}

	if err = binary.Read(reader, binary.LittleEndian, &b.Nonce); err != nil {
		return err
	}

	// Coinbase Tx Decoding
	{
		if err = b.Coinbase.FromReader(reader); err != nil {
			return err
		}
	}

	if txCount, err = utils.ReadCanonicalUvarint(reader); err != nil {
		return err
	} else if txCount > MaxTransactionCount {
		return fmt.Errorf("transaction count count too large: %d > %d", txCount, MaxTransactionCount)
	} else if txCount > 0 {
		// preallocate with soft cap
		b.Transactions = make([]types.Hash, 0, min(8192, txCount))

		for i := 0; i < int(txCount); i++ {
			if _, err = io.ReadFull(reader, transactionHash[:]); err != nil {
				return err
			}
			b.Transactions = append(b.Transactions, transactionHash)
		}
	}

	return nil
}

func (b *Block) Header() *Header {
	return &Header{
		MajorVersion: b.MajorVersion,
		MinorVersion: b.MinorVersion,
		Timestamp:    b.Timestamp,
		PreviousId:   b.PreviousId,
		Height:       b.Coinbase.GenHeight,
		Nonce:        b.Nonce,
		Reward:       b.Coinbase.TotalReward(),
		Id:           b.Id(),
		Difficulty:   types.ZeroDifficulty,
	}
}

func (b *Block) HeaderBlobBufferLength() int {
	return 1 + 1 +
		utils.UVarInt64Size(b.Timestamp) +
		types.HashSize +
		4
}

func (b *Block) HeaderBlob(preAllocatedBuf []byte) []byte {
	buf := preAllocatedBuf
	buf = append(buf, b.MajorVersion)
	buf = binary.AppendUvarint(buf, b.MinorVersion)
	buf = binary.AppendUvarint(buf, b.Timestamp)
	buf = append(buf, b.PreviousId[:]...)
	buf = binary.LittleEndian.AppendUint32(buf, b.Nonce)

	return buf
}

func (b *Block) HashingBlobBufferLength() int {
	return b.HeaderBlobBufferLength() +
		types.HashSize + utils.UVarInt64Size(len(b.Transactions)+1)
}

func (b *Block) HashingBlob(preAllocatedBuf []byte) []byte {
	buf := b.HeaderBlob(preAllocatedBuf)

	merkleTree := make(crypto.BinaryTreeHash, len(b.Transactions)+1)
	//TODO: cache?
	merkleTree[0] = b.Coinbase.CalculateId()
	copy(merkleTree[1:], b.Transactions)
	txTreeHash := merkleTree.RootHash()
	buf = append(buf, txTreeHash[:]...)

	buf = binary.AppendUvarint(buf, uint64(len(b.Transactions)+1))

	return buf
}

func (b *Block) Id() types.Hash {
	var varIntBuf [binary.MaxVarintLen64]byte
	buf := b.HashingBlob(make([]byte, 0, b.HashingBlobBufferLength()))
	return crypto.PooledKeccak256(varIntBuf[:binary.PutUvarint(varIntBuf[:], uint64(len(buf)))], buf)
}
