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
	"sync"

	"github.com/sphinx-core/go/src/consensus"
	types "github.com/sphinx-core/go/src/core/transaction"
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

// Blockchain manages the chain of blocks with state machine replication
type Blockchain struct {
	storage         *storage.Storage
	stateMachine    *storage.StateMachine
	chain           []*types.Block
	txIndex         map[string]*types.Transaction
	pendingTx       []*types.Transaction
	lock            sync.RWMutex
	status          BlockchainStatus
	syncMode        SyncMode
	consensusEngine *consensus.Consensus
}
