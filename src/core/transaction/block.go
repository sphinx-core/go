// MIT License
//
// Copyright (c) 2024 sphinx-core
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package types

import (
	"fmt"
	"math/big"
	"time"

	"github.com/sphinx-core/go/src/common"
)

// BlockHeader represents the metadata for a block in the blockchain.
type BlockHeader struct {
	Block      uint64   `json:"nblock"`      // The position of the block in the blockchain (index)
	Timestamp  int64    `json:"timestamp"`   // The timestamp when the block is mined
	PrevHash   []byte   `json:"prev_hash"`   // Hash of the previous block (direct predecessor)
	Difficulty *big.Int `json:"difficulty"`  // Difficulty level of mining the block
	Nonce      uint64   `json:"nonce"`       // The nonce used in mining
	TxsRoot    []byte   `json:"txs_root"`    // Merkle root of the transactions in the block
	StateRoot  []byte   `json:"state_root"`  // Merkle root of the state (EVM-like state)
	GasLimit   *big.Int `json:"gas_limit"`   // The maximum gas that can be used in the block
	GasUsed    *big.Int `json:"gas_used"`    // The actual gas used by the transactions
	ParentHash []byte   `json:"parent_hash"` // The hash of the parent block (alternative to PrevHash)
	UnclesHash []byte   `json:"uncles_hash"` // The hash of the uncles (previous block headers, also known as ommers)
}

// BlockBody represents the transactions and other data inside the block.
type BlockBody struct {
	TxsList    []*Transaction `json:"txs_list"`    // A list of transactions in the block
	UnclesHash []byte         `json:"uncles_hash"` // Hash representing uncles (previous block headers, ommers)
}

// Block represents the entire block structure including the header and body.
type Block struct {
	Header BlockHeader `json:"header"` // Block metadata
	Body   BlockBody   `json:"body"`   // Block transactions and uncles
}

// Transaction represents a single transaction within the block.
type Transaction struct {
	Sender    string   `json:"sender"`
	Receiver  string   `json:"receiver"`
	Amount    *big.Int `json:"amount"`
	GasLimit  *big.Int `json:"gas_limit"`
	GasPrice  *big.Int `json:"gas_price"`
	Timestamp int64    `json:"timestamp"`
	Nonce     uint64   `json:"nonce"`
}

// NewBlockHeader creates a new BlockHeader.
func NewBlockHeader(nBlock uint64, prevHash []byte, difficulty *big.Int, txsRoot, stateRoot []byte, gasLimit, gasUsed *big.Int, parentHash, unclesHash []byte) *BlockHeader {
	return &BlockHeader{
		Block:      nBlock, // Set nBlock as the block's position in the chain
		Timestamp:  time.Now().Unix(),
		PrevHash:   prevHash,
		Difficulty: difficulty,
		Nonce:      uint64(0), // Default nonce is 0, will be adjusted during mining
		TxsRoot:    txsRoot,
		StateRoot:  stateRoot,
		GasLimit:   gasLimit,
		GasUsed:    gasUsed,
		ParentHash: parentHash,
		UnclesHash: unclesHash,
	}
}

// NewBlockBody creates a new BlockBody with a list of transactions and uncles hash.
func NewBlockBody(txsList []*Transaction, unclesHash []byte) *BlockBody {
	return &BlockBody{
		TxsList:    txsList,
		UnclesHash: unclesHash,
	}
}

// NewBlock creates a new Block using the given header and body.
func NewBlock(header *BlockHeader, body *BlockBody) *Block {
	return &Block{
		Header: *header,
		Body:   *body,
	}
}

// GenerateBlockHash generates the hash of the block using the BlockHeader's fields and SphinxHash.
func (b *Block) GenerateBlockHash() []byte {
	// Concatenate the fields of BlockHeader and BlockBody to generate the block hash
	headerData := append(b.Header.PrevHash, b.Header.TxsRoot...)
	headerData = append(headerData, b.Header.StateRoot...)
	headerData = append(headerData, b.Header.ParentHash...)
	headerData = append(headerData, b.Header.UnclesHash...)

	// Use common.SpxHash to hash the concatenated data
	return common.SpxHash(headerData)
}

// MineBlock adjusts the nonce in the BlockHeader until a valid block hash is found.
func (b *Block) MineBlock() {
	for {
		// Generate the block hash
		blockHash := b.GenerateBlockHash()

		// Check if the hash meets the difficulty criteria
		if meetsDifficulty(blockHash, b.Header.Difficulty) {
			break
		}

		// Increment the nonce and try again
		b.Header.Nonce++
	}
}

// meetsDifficulty checks if the block hash meets the mining difficulty.
func meetsDifficulty(hash []byte, difficulty *big.Int) bool {
	// Check if the hash meets the difficulty, e.g., the hash must be less than the difficulty
	hashBigInt := new(big.Int).SetBytes(hash)
	return hashBigInt.Cmp(difficulty) == -1
}

// AddTxs adds a transaction to the block's body.
func (b *Block) AddTxs(tx *Transaction) {
	b.Body.TxsList = append(b.Body.TxsList, tx)
}

// Example of a function to create a transaction
func NewTxs(to, from string, fee float64, storage string, nonce uint64, gasLimit, gasPrice *big.Int, block *Block, key string) error {
	// Create a new Note
	note, err := NewNote(to, from, fee, storage, key)
	if err != nil {
		return err
	}

	// Convert the Note to a Transaction
	tx := note.ToTxs(nonce, gasLimit, gasPrice)

	// Add the Transaction to the Block
	block.AddTxs(tx)

	return nil
}

// SanityCheck verifies the validity and integrity of the block's header and body.
func (b *Block) SanityCheck() error {
	// Check if the timestamp is valid (not in the future)
	if b.Header.Timestamp > time.Now().Unix() {
		return fmt.Errorf("invalid timestamp: %d", b.Header.Timestamp)
	}

	// Ensure PrevHash is not empty (except for the genesis block)
	if b.Header.Block > 0 && len(b.Header.PrevHash) == 0 {
		return fmt.Errorf("previous hash is missing for block number: %d", b.Header.Block)
	}

	// Check if Difficulty is non-negative
	if b.Header.Difficulty.Sign() == -1 {
		return fmt.Errorf("invalid difficulty: %s", b.Header.Difficulty.String())
	}

	// Ensure TxRoot and StateRoot are not empty
	if len(b.Header.TxsRoot) == 0 {
		return fmt.Errorf("transaction root is missing")
	}
	if len(b.Header.StateRoot) == 0 {
		return fmt.Errorf("state root is missing")
	}

	// Check GasUsed does not exceed GasLimit
	if b.Header.GasUsed.Cmp(b.Header.GasLimit) > 0 {
		return fmt.Errorf("gas used (%s) exceeds gas limit (%s)", b.Header.GasUsed.String(), b.Header.GasLimit.String())
	}

	// Validate ParentHash and UnclesHash if uncles are present
	if len(b.Body.UnclesHash) > 0 && len(b.Header.UnclesHash) == 0 {
		return fmt.Errorf("uncles hash mismatch")
	}

	// Ensure all transactions in the body are valid
	for _, tx := range b.Body.TxsList {
		if err := tx.SanityCheck(); err != nil {
			return fmt.Errorf("invalid transaction: %v", err)
		}
	}

	return nil
}

// SanityCheck verifies the validity of a transaction.
func (tx *Transaction) SanityCheck() error {
	// Ensure sender and receiver addresses are not empty
	if tx.Sender == "" {
		return fmt.Errorf("transaction sender is missing")
	}
	if tx.Receiver == "" {
		return fmt.Errorf("transaction receiver is missing")
	}

	// Ensure the amount is non-negative
	if tx.Amount.Sign() == -1 {
		return fmt.Errorf("transaction amount is negative")
	}

	// Check gas limit and gas price are non-negative
	if tx.GasLimit.Sign() == -1 {
		return fmt.Errorf("invalid gas limit: %s", tx.GasLimit.String())
	}
	if tx.GasPrice.Sign() == -1 {
		return fmt.Errorf("invalid gas price: %s", tx.GasPrice.String())
	}

	return nil
}
