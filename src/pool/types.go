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
package pool

import (
	"math/big"
	"sync"
	"time"

	types "github.com/sphinx-core/go/src/core/transaction"
)

// TransactionStatus represents the state of a transaction in the pool
type TransactionStatus int

const (
	StatusBroadcast  TransactionStatus = iota // Newly broadcast, not yet validated
	StatusPending                             // Validated and waiting for block inclusion
	StatusValidating                          // Currently being validated
	StatusInvalid                             // Failed validation
	StatusExpired                             // Transaction expired
)

// PoolType distinguishes between different pool types
type PoolType int

const (
	PoolTypeBroadcast  PoolType = iota // For incoming broadcast transactions
	PoolTypePending                    // For validated transactions waiting for blocks
	PoolTypeValidation                 // For transactions undergoing validation
)

// MempoolConfig defines configuration for the mempool
type MempoolConfig struct {
	MaxSize           int
	MaxBytes          uint64
	MaxTxSize         uint64
	BlockGasLimit     *big.Int
	ValidationTimeout time.Duration
	ExpiryTime        time.Duration
	MaxBroadcastSize  int
	MaxPendingSize    int
}

// PooledTransaction wraps transaction with metadata
type PooledTransaction struct {
	Transaction *types.Transaction
	Status      TransactionStatus
	FirstSeen   time.Time
	LastUpdated time.Time
	RetryCount  int
	Error       string
	Priority    int // Higher priority transactions get included first
}

// Mempool manages all transaction pools (broadcast, pending, validation)
type Mempool struct {
	lock sync.RWMutex

	// Main pools
	broadcastPool  map[string]*PooledTransaction // Newly broadcast transactions
	pendingPool    map[string]*PooledTransaction // Validated transactions waiting for blocks
	validationPool map[string]*PooledTransaction // Transactions being validated
	invalidPool    map[string]*PooledTransaction // Failed transactions (for monitoring)

	// Indexes for quick lookup
	allTransactions map[string]*PooledTransaction

	// Configuration
	config *MempoolConfig

	// Memory tracking
	currentBytes uint64 // ADD THIS FIELD - tracks total bytes used by transactions

	// Statistics
	stats struct {
		totalAdded     uint64
		totalValidated uint64
		totalInvalid   uint64
		totalExpired   uint64
		totalBroadcast uint64
		validationTime time.Duration
	}

	// Channels for coordination
	broadcastChan  chan *types.Transaction
	validationChan chan *PooledTransaction
	cleanupChan    chan struct{}

	// Control
	stopChan chan struct{}
	running  bool
}
