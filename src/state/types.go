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
// go/src/state/types.go
package state

import (
	"sync"
	"time"

	"github.com/sphinx-core/go/src/consensus"
	types "github.com/sphinx-core/go/src/core/transaction"
)

type OperationType int

// NetworkBroadcaster defines methods used by StateMachine to broadcast operations
type NetworkBroadcaster interface {
	BroadcastOperation(op *Operation) error
	BroadcastCommitProof(proof *CommitProof) error
}

// BlockStorage defines the interface for block storage operations
type BlockStorage interface {
	StoreBlock(block *types.Block) error
	GetBlockByHash(hash string) (*types.Block, error)
	GetBlockByHeight(height uint64) (*types.Block, error)
	GetLatestBlock() (*types.Block, error)
	GetTransaction(txID string) (*types.Transaction, error)
	GetTotalBlocks() uint64 // Changed from int to uint64
	ValidateChain() error
	Close() error
}

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

	// Final state tracking for replication
	finalStates []*FinalStateInfo
	stateMutex  sync.RWMutex
}

// Storage manages blockchain data persistence
type Storage struct {
	mu sync.RWMutex

	dataDir   string
	blocksDir string
	indexDir  string
	stateDir  string

	// In-memory indices for fast access
	blockIndex  map[string]*types.Block       // hash -> block
	heightIndex map[uint64]*types.Block       // height -> block
	txIndex     map[string]*types.Transaction // txID -> transaction

	// Chain state
	bestBlockHash string
	totalBlocks   uint64
}

// ChainParams represents basic chain parameters for storage
type ChainParams struct {
	ChainID       uint64
	ChainName     string
	Symbol        string
	GenesisTime   int64
	GenesisHash   string
	Version       string
	MagicNumber   uint32
	DefaultPort   int
	BIP44CoinType uint64
	LedgerName    string
}

// BasicChainState represents basic chain state
type BasicChainState struct {
	BestBlockHash string `json:"best_block_hash"`
	TotalBlocks   uint64 `json:"total_blocks"`
	LastUpdated   string `json:"last_updated"`
}

// BlockSizeMetrics with human-readable MB fields
type BlockSizeMetrics struct {
	TotalBlocks     uint64          `json:"total_blocks"`
	AverageSize     uint64          `json:"average_size_bytes"`
	MinSize         uint64          `json:"min_size_bytes"`
	MaxSize         uint64          `json:"max_size_bytes"`
	TotalSize       uint64          `json:"total_size_bytes"`
	SizeStats       []BlockSizeInfo `json:"size_stats"`
	CalculationTime string          `json:"calculation_time"`

	// Human-readable MB fields
	AverageSizeMB float64 `json:"average_size_mb"`
	MinSizeMB     float64 `json:"min_size_mb"`
	MaxSizeMB     float64 `json:"max_size_mb"`
	TotalSizeMB   float64 `json:"total_size_mb"`
}

// BlockSizeInfo with MB field
type BlockSizeInfo struct {
	Height    uint64  `json:"height"`
	Hash      string  `json:"hash"`
	Size      uint64  `json:"size_bytes"`
	SizeMB    float64 `json:"size_mb"`
	TxCount   uint64  `json:"transaction_count"`
	Timestamp int64   `json:"timestamp"`
}

// ChainState represents the complete chain state
type ChainState struct {
	// Chain identification
	ChainIdentification *ChainIdentification `json:"chain_identification"`

	// Node information
	Nodes []*NodeInfo `json:"nodes"`

	// Storage state
	StorageState *StorageState `json:"storage_state"`

	// Basic chain state
	BasicChainState *BasicChainState `json:"basic_chain_state"`

	// Block size metrics
	BlockSizeMetrics *BlockSizeMetrics `json:"block_size_metrics"`

	// Timestamp
	Timestamp string `json:"timestamp"`

	// Signature validation section (now simplified)
	SignatureValidation *SignatureValidation `json:"signature_validation,omitempty"`

	// REPLACED: ConsensusSignatures with FinalStateInfo array
	FinalStates []*FinalStateInfo `json:"final_states,omitempty"`
}

type SignatureValidation struct {
	TotalSignatures   int    `json:"total_signatures"`
	ValidSignatures   int    `json:"valid_signatures"`
	InvalidSignatures int    `json:"invalid_signatures"`
	ValidationTime    string `json:"validation_time"`
}

// FINAL STATE INFO - MERGED ConsensusSignature and FinalStateInfo
type FinalStateInfo struct {
	// Block identification
	BlockHash   string `json:"block_hash"`
	BlockHeight uint64 `json:"block_height"`
	MerkleRoot  string `json:"merkle_root"`

	// Node information
	NodeID      string `json:"node_id,omitempty"`
	NodeName    string `json:"node_name,omitempty"`
	NodeAddress string `json:"node_address,omitempty"`

	// Chain state
	TotalBlocks uint64 `json:"total_blocks,omitempty"`
	Status      string `json:"status"` // "proposed", "prepared", "committed", "timeout"

	// Signature information (merged from ConsensusSignature)
	SignerNodeID string `json:"signer_node_id,omitempty"` // Who signed (from ConsensusSignature)
	Signature    string `json:"signature"`                // hex encoded signature
	MessageType  string `json:"message_type"`             // "proposal", "prepare", "commit", "timeout"
	View         uint64 `json:"view"`                     // Consensus view number
	Valid        bool   `json:"valid"`                    // Signature validity

	// Additional context
	ProposerID       string `json:"proposer_id,omitempty"`       // Who proposed the block
	SignatureStatus  string `json:"signature_status,omitempty"`  // "Valid", "Invalid", "Pending"
	VerificationTime string `json:"verification_time,omitempty"` // When signature was verified

	// Timestamps
	Timestamp      string `json:"timestamp"`                 // When this final state was created
	BlockTimestamp int64  `json:"block_timestamp,omitempty"` // Original block timestamp
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

	// UPDATED: Use FinalStateInfo instead of ConsensusSignature
	FinalStates []*FinalStateInfo `json:"final_states,omitempty"`
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

// NodeInfo represents information about a network node
type NodeInfo struct {
	NodeID      string                 `json:"node_id"`
	NodeName    string                 `json:"node_name"`
	NodeAddress string                 `json:"node_address"`
	ChainInfo   map[string]interface{} `json:"chain_info"`
	BlockHeight uint64                 `json:"block_height"`
	BlockHash   string                 `json:"block_hash"`
	MerkleRoot  string                 `json:"merkle_root"`
	Timestamp   string                 `json:"timestamp"`

	// UPDATED: FinalState is now a single FinalStateInfo instead of separate struct
	FinalState *FinalStateInfo `json:"final_state"`
}

// BlockInfo represents detailed block information
type BlockInfo struct {
	Height           uint64   `json:"height"`
	Hash             string   `json:"hash"`
	PreviousHash     string   `json:"previous_hash"`
	MerkleRoot       string   `json:"merkle_root"`
	Timestamp        int64    `json:"timestamp"`
	Difficulty       string   `json:"difficulty"`
	Nonce            uint64   `json:"nonce"`
	GasLimit         string   `json:"gas_limit"`
	GasUsed          string   `json:"gas_used"`
	TransactionCount int      `json:"transaction_count"`
	Transactions     []string `json:"transactions,omitempty"`
	MagicNumber      uint32   `json:"magic_number"`
}

// StorageState represents the storage layer state
type StorageState struct {
	BestBlockHash string `json:"best_block_hash"`
	TotalBlocks   uint64 `json:"total_blocks"`
	BlocksDir     string `json:"blocks_dir"`
	IndexDir      string `json:"index_dir"`
	StateDir      string `json:"state_dir"`
}
