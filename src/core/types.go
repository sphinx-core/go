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

// go/src/core/types.go
package core

import (
	"math/big"
	"sync"
	"time"

	"github.com/sphinx-core/go/src/consensus"
	types "github.com/sphinx-core/go/src/core/transaction"
	"github.com/sphinx-core/go/src/pool"
	storage "github.com/sphinx-core/go/src/state"
)

// BlockchainStatus represents the current status of the blockchain
type BlockchainStatus int

// SyncMode represents different synchronization modes for the blockchain
type SyncMode int

// BlockImportResult represents the outcome of importing a new block
type BlockImportResult int

// CacheType represents different types of caches used in the blockchain
type CacheType int

// SphinxChainParameters defines the complete blockchain parameters
type SphinxChainParameters struct {
	// Network Identification
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
	Denominations map[string]*big.Int

	// Block Configuration
	MaxBlockSize       uint64
	MaxTransactionSize uint64
	TargetBlockSize    uint64
	BlockGasLimit      *big.Int

	// Mempool Configuration
	MempoolConfig *pool.MempoolConfig

	// Consensus Configuration
	ConsensusConfig *ConsensusConfig

	// Performance Configuration
	PerformanceConfig *PerformanceConfig
}

// ConsensusConfig defines consensus-related parameters
type ConsensusConfig struct {
	BlockTime        time.Duration
	EpochLength      uint64
	ValidatorSetSize int
	MaxValidators    int
	MinStakeAmount   *big.Int
	UnbondingPeriod  time.Duration
	SlashingEnabled  bool
	DoubleSignSlash  *big.Int // Slashing amount for double signing
}

// PerformanceConfig defines performance-related parameters
type PerformanceConfig struct {
	MaxConcurrentValidations int
	ValidationTimeout        time.Duration
	CacheSize                int
	PruningInterval          time.Duration
	MaxPeers                 int
	SyncBatchSize            int
}

// Blockchain manages the chain of blocks with state machine replication
type Blockchain struct {
	storage         *storage.Storage
	stateMachine    *storage.StateMachine
	mempool         *pool.Mempool
	chain           []*types.Block
	txIndex         map[string]*types.Transaction
	pendingTx       []*types.Transaction
	lock            sync.RWMutex
	status          BlockchainStatus
	syncMode        SyncMode
	consensusEngine *consensus.Consensus
	chainParams     *SphinxChainParameters
}
