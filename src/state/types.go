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

// go/src/state/types.go
package state

import (
	"sync"
	"time"

	"github.com/sphinx-core/go/src/consensus"
	types "github.com/sphinx-core/go/src/core/transaction"
)

type OperationType int

// StateMachine manages state machine replication for blockchain
type StateMachine struct {
	mu sync.RWMutex

	storage   *Storage
	consensus *consensus.Consensus
	nodeID    string

	// Replication state
	currentState *StateSnapshot
	stateHistory map[uint64]*StateSnapshot // height -> state snapshot
	pendingOps   []*Operation

	// Validation
	validators  map[string]bool // nodeID -> isValidator
	quorumSize  int
	currentView uint64
	lastApplied uint64

	// Channels
	opCh      chan *Operation
	stateCh   chan *StateSnapshot
	commitCh  chan *CommitProof
	timeoutCh chan struct{}
}

// Add this struct to represent basic chain state
type BasicChainState struct {
	BestBlockHash string `json:"best_block_hash"`
	TotalBlocks   uint64 `json:"total_blocks"`
	LastUpdated   string `json:"last_updated"`
}

// Update ChainState to include basic chain state
type ChainState struct {
	// Chain identification
	ChainIdentification *ChainIdentification `json:"chain_identification"`

	// Node information
	Nodes []*NodeInfo `json:"nodes"`

	// Storage state
	StorageState *StorageState `json:"storage_state"`

	// Basic chain state (merged from basic_chain_state.json)
	BasicChainState *BasicChainState `json:"basic_chain_state"`

	// Timestamp
	Timestamp string `json:"timestamp"`
}

// Operation represents a state machine operation (block or transaction)
type Operation struct {
	Type        OperationType      `json:"type"`
	Block       *types.Block       `json:"block,omitempty"`
	Transaction *types.Transaction `json:"transaction,omitempty"`
	View        uint64             `json:"view"`
	Sequence    uint64             `json:"sequence"`
	Proposer    string             `json:"proposer"`
	Signature   []byte             `json:"signature"`
}

// StateSnapshot represents a snapshot of the blockchain state
type StateSnapshot struct {
	Height     uint64                   `json:"height"`
	BlockHash  string                   `json:"block_hash"`
	StateRoot  string                   `json:"state_root"`
	Timestamp  time.Time                `json:"timestamp"`
	Validators map[string]bool          `json:"validators"`
	UTXOSet    map[string]*types.UTXO   `json:"utxo_set"`
	Accounts   map[string]*AccountState `json:"accounts"`
	Committed  bool                     `json:"committed"`
}

// AccountState represents account state in the state machine
type AccountState struct {
	Address  string  `json:"address"`
	Balance  *BigInt `json:"balance"`
	Nonce    uint64  `json:"nonce"`
	CodeHash string  `json:"code_hash"`
}

// BigInt wrapper for JSON serialization
type BigInt struct {
	Value string `json:"value"`
}

// CommitProof represents proof of commitment for a state
type CommitProof struct {
	Height     uint64            `json:"height"`
	BlockHash  string            `json:"block_hash"`
	Signatures map[string][]byte `json:"signatures"` // nodeID -> signature
	View       uint64            `json:"view"`
	Quorum     int               `json:"quorum"`
}

// ChainIdentification represents blockchain identification parameters
type ChainIdentification struct {
	Timestamp   string                 `json:"timestamp"`
	ChainParams map[string]interface{} `json:"chain_parameters"`
	TokenInfo   map[string]interface{} `json:"token_info"`
	WalletPaths map[string]string      `json:"wallet_derivation_paths"`
	NetworkInfo map[string]interface{} `json:"network_info"`
}

// TestSummary represents test execution results
type TestSummary struct {
	TestName      string `json:"test_name"`
	Timestamp     string `json:"timestamp"`
	NumNodes      int    `json:"num_nodes"`
	TestDuration  string `json:"test_duration"`
	Success       bool   `json:"success"`
	FinalHeight   uint64 `json:"final_height"`
	GenesisHash   string `json:"genesis_hash"`
	ConsensusType string `json:"consensus_type"`
}

// NodeInfo represents information about a single node
type NodeInfo struct {
	NodeID      string                 `json:"node_id"`
	NodeName    string                 `json:"node_name"`
	ChainInfo   map[string]interface{} `json:"chain_info"`
	BlockHeight uint64                 `json:"block_height"`
	BlockHash   string                 `json:"block_hash"`
	Timestamp   string                 `json:"timestamp"`
	FinalState  *FinalStateInfo        `json:"final_state"`
}

// FinalStateInfo represents the final state of a node
type FinalStateInfo struct {
	BlockHeight uint64 `json:"block_height"`
	BlockHash   string `json:"block_hash"`
	TotalBlocks uint64 `json:"total_blocks"`
	Status      string `json:"status"`
	Timestamp   string `json:"timestamp"`
}

// StorageState represents the storage layer state
type StorageState struct {
	BestBlockHash string `json:"best_block_hash"`
	TotalBlocks   uint64 `json:"total_blocks"`
	BlocksDir     string `json:"blocks_dir"`
	IndexDir      string `json:"index_dir"`
	StateDir      string `json:"state_dir"`
}
