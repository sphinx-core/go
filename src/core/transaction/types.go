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

// go/src/core/transaction/types.go
package types

import (
	"math/big"
	"sync"
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
	ID        string   `json:"id"`        // Unique transaction identifier (hash)
	Sender    string   `json:"sender"`    // Sender’s address
	Receiver  string   `json:"receiver"`  // Receiver’s address
	Amount    *big.Int `json:"amount"`    // Amount transferred
	GasLimit  *big.Int `json:"gas_limit"` // Maximum gas allowed
	GasPrice  *big.Int `json:"gas_price"` // Price per gas unit
	Timestamp int64    `json:"timestamp"` // Transaction creation time
	Nonce     uint64   `json:"nonce"`     // Transaction nonce
}

// Outpoint represents a specific transaction output.
type Outpoint struct {
	TxID  string `json:"txid"`  // Transaction ID
	Index int    `json:"index"` // Output index
}

// UTXO represents an unspent transaction output.
type UTXO struct {
	Outpoint Outpoint `json:"outpoint"`
	Value    uint64   `json:"value"`
	Address  string   `json:"address"`
	Coinbase bool     `json:"coinbase"`
	Spent    bool     `json:"spent"`
	Height   uint64   `json:"height"`
}

// UTXOSet manages unspent transaction outputs.
type UTXOSet struct {
	mu          sync.RWMutex
	utxos       map[Outpoint]*UTXO
	totalSupply *big.Int
}

// Output represents a transaction output.
type Output struct {
	Value   uint64 `json:"value"`
	Address string `json:"address"`
}

// Note represents a transaction receipt.
type Note struct {
	To        string  `json:"to"`
	From      string  `json:"from"`
	Fee       float64 `json:"fee"`
	Storage   string  `json:"storage"`
	Timestamp int64   `json:"timestamp"`
	MAC       string  `json:"mac"`
	Output    *Output `json:"output"`
}

// Contract represents a transaction contract.
type Contract struct {
	Sender    string   `json:"sender"`
	Receiver  string   `json:"receiver"`
	Amount    *big.Int `json:"amount"`
	Fee       *big.Int `json:"fee"`
	Storage   string   `json:"storage"`
	Timestamp int64    `json:"timestamp"`
}

// Validator validates transaction notes.
type Validator struct {
	senderAddress    string
	recipientAddress string
}
