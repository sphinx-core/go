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
