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

// go/src/consensus/types.go
package consensus

import (
	"context"
	"math/big"
	"sync"
	"time"

	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
	"github.com/sphinx-core/go/src/core/hashtree"
	key "github.com/sphinx-core/go/src/core/sphincs/key/backend"
	sign "github.com/sphinx-core/go/src/core/sphincs/sign/backend"
)

// Block interface that your existing types.Block will satisfy
// This interface defines the minimum required methods for a block
// to participate in the consensus protocol
type Block interface {
	GetHeight() uint64       // Returns the block height/sequence number
	GetHash() string         // Returns the cryptographic hash of the block
	GetPrevHash() string     // Returns the hash of the previous block
	GetTimestamp() int64     // Returns the block creation timestamp
	Validate() error         // Validates the block structure and contents
	GetDifficulty() *big.Int // Returns the block difficulty
}

// BlockWithBody extends the basic Block interface for blocks that have bodies
type BlockWithBody interface {
	Block
	GetBody() interface{} // Returns the block body (for transaction access)
}

// Proposal represents a block proposal from a leader
// This is the initial message in the PBFT protocol where the leader
// proposes a new block for the current consensus round
type Proposal struct {
	Block      Block  `json:"block"`       // The proposed block to be committed
	View       uint64 `json:"view"`        // The consensus view number this proposal belongs to
	ProposerID string `json:"proposer_id"` // ID of the node making this proposal
	Signature  []byte `json:"signature"`   // Cryptographic signature of the proposer
}

// Vote represents a vote from a validator
// Validators send votes to indicate agreement with proposed blocks
// There are two types of votes: prepare votes and commit votes
type Vote struct {
	BlockHash string `json:"block_hash"` // Hash of the block being voted on
	View      uint64 `json:"view"`       // Consensus view number for this vote
	VoterID   string `json:"voter_id"`   // ID of the validator casting this vote
	Signature []byte `json:"signature"`  // Cryptographic signature of the voter
}

// BlockChain interface for block storage and retrieval
// This interface abstracts the blockchain storage layer from consensus logic
// allowing different blockchain implementations to work with the consensus engine
type BlockChain interface {
	GetLatestBlock() Block            // Returns the most recent block in the chain
	ValidateBlock(block Block) error  // Validates a block against chain rules
	CommitBlock(block Block) error    // Permanently adds a block to the chain
	GetBlockByHash(hash string) Block // Retrieves a block by its hash
}

// NodeManager interface to abstract network functionality
// This interface provides network communication capabilities for the consensus engine
// allowing it to interact with other nodes without knowing network implementation details
type NodeManager interface {
	GetPeers() map[string]Peer                                   // Returns all connected peers
	GetNode(nodeID string) Node                                  // Returns node information by ID
	BroadcastMessage(messageType string, data interface{}) error // Sends message to all peers
}

// Node interface represents a participant in the network
// This provides basic information about network participants
type Node interface {
	GetID() string         // Returns the unique identifier of the node
	GetRole() NodeRole     // Returns the role of the node (validator, observer, etc.)
	GetStatus() NodeStatus // Returns the current status of the node
}

// Peer interface represents a connection to another node
// Peers are the network connections through which consensus messages flow
type Peer interface {
	GetNode() Node // Returns the node information for this peer connection
}

// NodeRole represents the role of a node in the network
// Different roles have different responsibilities in the consensus process
type NodeRole int

// NodeStatus represents the status of a node
// Status indicates whether a node is active, syncing, or unavailable
type NodeStatus int

// ConsensusPhase represents the current phase of the consensus protocol
// PBFT progresses through several phases: idle, pre-prepared, prepared, committed
type ConsensusPhase int

// Update the Consensus struct to include the missing fields
type Consensus struct {
	mu sync.RWMutex // Read-write mutex for thread-safe access to consensus state

	// Node and network references
	nodeID      string      // Unique identifier for this node
	nodeManager NodeManager // Network communication interface
	blockChain  BlockChain  // Blockchain storage interface

	// Consensus state - these variables track the current progress of consensus
	currentView    uint64         // Current consensus view/round number
	currentHeight  uint64         // Current blockchain height
	phase          ConsensusPhase // Current phase in PBFT protocol
	lockedBlock    Block          // Block that is locked after prepare phase (safety guarantee)
	preparedBlock  Block          // Block that has been prepared but not yet locked
	preparedView   uint64         // View in which the block was prepared
	signingService *SigningService

	// Vote tracking - these data structures collect and count votes from validators
	receivedVotes    map[string]map[string]*Vote // blockHash -> voterID -> commit votes
	prepareVotes     map[string]map[string]*Vote // blockHash -> voterID -> prepare votes
	sentVotes        map[string]bool             // Tracks which commit votes this node has sent
	sentPrepareVotes map[string]bool             // Tracks which prepare votes this node has sent

	// Configuration - these parameters control consensus behavior
	quorumFraction float64       // Fraction of nodes required for quorum (typically 2/3)
	timeout        time.Duration // Timeout duration for view changes
	isLeader       bool          // Whether this node is the current leader

	// Channels for consensus messages - these channels receive messages from the network
	proposalCh chan *Proposal   // Channel for receiving block proposals
	voteCh     chan *Vote       // Channel for receiving commit votes
	timeoutCh  chan *TimeoutMsg // Channel for receiving timeout messages
	prepareCh  chan *Vote       // Channel for receiving prepare votes

	// Callbacks - functions called at important consensus events
	onCommit func(Block) error // Callback executed when a block is successfully committed

	ctx            context.Context    // Context for graceful shutdown and cancellation
	cancel         context.CancelFunc // Function to cancel the context and stop consensus
	lastViewChange time.Time          // Track last view change time

	// ADD THESE MISSING FIELDS:
	viewChangeMutex sync.Mutex // Dedicated mutex for view change synchronization

	// View change and timing control
	lastBlockTime time.Time // Last time a block was committed

	consensusSignatures []*ConsensusSignature
	signatureMutex      sync.RWMutex

	// Add this field to track pending proposals for recovery
	pendingProposal *Proposal
}

// SigningService handles cryptographic signing for consensus messages
type SigningService struct {
	sphincsManager    *sign.SphincsManager
	keyManager        *key.KeyManager
	nodeID            string
	privateKey        *sphincs.SPHINCS_SK
	publicKey         *sphincs.SPHINCS_PK
	publicKeyRegistry map[string]*sphincs.SPHINCS_PK // Add this
	registryMutex     sync.RWMutex                   // Add this
}

// SignedMessage represents a complete signed message with all components
type SignedMessage struct {
	Signature  []byte                 // Raw SPHINCS+ signature bytes
	Timestamp  []byte                 // Timestamp
	Nonce      []byte                 // Nonce
	MerkleRoot *hashtree.HashTreeNode // Merkle root
	Data       []byte                 // Original message data
}

// ConsensusSignature represents a captured signature from consensus messages
// This type stores cryptographic signatures for audit and verification purposes
// ConsensusSignature represents a captured signature from consensus messages
type ConsensusSignature struct {
	BlockHash    string `json:"block_hash"`
	BlockHeight  uint64 `json:"block_height"`
	SignerNodeID string `json:"signer_node_id"`
	Signature    string `json:"signature"`
	MessageType  string `json:"message_type"`
	View         uint64 `json:"view"`
	Timestamp    string `json:"timestamp"`
	Valid        bool   `json:"valid"`
}

// SignatureValidation contains statistics about signature validation
type SignatureValidation struct {
	TotalSignatures   int    `json:"total_signatures"`
	ValidSignatures   int    `json:"valid_signatures"`
	InvalidSignatures int    `json:"invalid_signatures"`
	ValidationTime    string `json:"validation_time"`
}

// BlockSizeMetrics contains block size statistics
type BlockSizeMetrics struct {
	TotalBlocks     int                      `json:"total_blocks"`
	AverageSize     uint64                   `json:"average_size_bytes"`
	MinSize         uint64                   `json:"min_size_bytes"`
	MaxSize         uint64                   `json:"max_size_bytes"`
	TotalSize       uint64                   `json:"total_size_bytes"`
	SizeStats       []map[string]interface{} `json:"size_stats"`
	CalculationTime string                   `json:"calculation_time"`
	AverageSizeMB   float64                  `json:"average_size_mb"`
	MinSizeMB       float64                  `json:"min_size_mb"`
	MaxSizeMB       float64                  `json:"max_size_mb"`
	TotalSizeMB     float64                  `json:"total_size_mb"`
}

// Update TimeoutMsg to include timestamp
type TimeoutMsg struct {
	View      uint64 `json:"view"`      // The new view number being requested
	VoterID   string `json:"voter_id"`  // ID of the node requesting view change
	Signature []byte `json:"signature"` // Cryptographic signature of the requester
	Timestamp int64  `json:"timestamp"` // When this timeout was created
}

// QuorumVerifier provides mathematical guarantees for BFT safety
// This struct contains the parameters needed to verify that the system
// can tolerate Byzantine faults while maintaining safety and liveness
type QuorumVerifier struct {
	totalNodes     int     // Total number of nodes in the network
	faultyNodes    int     // Number of faulty (Byzantine) nodes to tolerate
	quorumFraction float64 // Fraction of nodes required for quorum decisions
}

// QuorumCalculator implements the mathematical quorum guarantees
// This struct performs calculations related to quorum sizes and fault tolerance
// ensuring the system meets Byzantine Fault Tolerance requirements
type QuorumCalculator struct {
	quorumFraction float64 // The quorum fraction used for all calculations
}

// ConsensusState manages the state machine for consensus protocol
// This struct encapsulates all the state variables needed for PBFT consensus
// and provides thread-safe access through mutex protection
type ConsensusState struct {
	mu             sync.RWMutex
	currentView    uint64
	currentHeight  uint64
	phase          ConsensusPhase
	lockedBlock    Block
	preparedBlock  Block
	preparedView   uint64
	lastViewChange time.Time
}
