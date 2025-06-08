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

// core/blockchain.go
package core

import (
	"errors"
	"fmt"
	"log"
	"sync"

	types "github.com/sphinx-core/go/src/core/transaction"
)

// Blockchain manages the chain of blocks, including the active chain.
type Blockchain struct {
	chain      []*types.Block          // Active chain of blocks
	blockIndex map[string]*types.Block // Fast lookup for blocks by hash
	pendingTx  []types.Transaction     // Pending transactions
	bestBlock  *types.Block            // Tip of the active chain
	lock       sync.RWMutex
}

// NewBlockchain initializes a blockchain with a genesis block.
func NewBlockchain() *Blockchain {
	genesis := &types.Block{
		Header: types.Header{
			Block:    0,
			PrevHash: []byte{},
		},
		Transactions: []types.Transaction{},
	}
	genesis.Hash = genesis.GenerateBlockHash()
	bc := &Blockchain{
		chain:      []*types.Block{genesis},
		blockIndex: map[string]*types.Block{string(genesis.Hash): genesis},
		pendingTx:  []types.Transaction{},
		bestBlock:  genesis,
	}
	log.Printf("Initialized blockchain with genesis block: Hash=%x", genesis.Hash)
	return bc
}

// AddTransaction adds a transaction to the pending list.
func (bc *Blockchain) AddTransaction(tx types.Transaction) error {
	bc.lock.Lock()
	defer bc.lock.Unlock()

	if tx.From == "" || tx.To == "" || tx.Amount <= 0 {
		return errors.New("invalid transaction")
	}
	bc.pendingTx = append(bc.pendingTx, tx)
	log.Printf("Added transaction: %+v", tx)
	return nil
}

// AddBlock creates a new block from pending transactions.
func (bc *Blockchain) AddBlock() error {
	bc.lock.Lock()
	defer bc.lock.Unlock()

	if len(bc.pendingTx) == 0 {
		return errors.New("no pending transactions")
	}

	prevBlock := bc.bestBlock
	newBlock := &types.Block{
		Header: types.Header{
			Block:    prevBlock.Header.Block + 1,
			PrevHash: prevBlock.Hash,
		},
		Transactions: bc.pendingTx,
	}
	newBlock.Hash = newBlock.GenerateBlockHash()

	// Validate block
	if err := newBlock.SanityCheck(); err != nil {
		return fmt.Errorf("block failed sanity check: %w", err)
	}
	if string(newBlock.Header.PrevHash) != string(prevBlock.Hash) {
		return errors.New("block does not correctly reference previous block")
	}

	// Add to chain and index
	blockHash := string(newBlock.Hash)
	bc.chain = append(bc.chain, newBlock)
	bc.blockIndex[blockHash] = newBlock
	bc.bestBlock = newBlock
	bc.pendingTx = []types.Transaction{}
	log.Printf("Added block to active chain: Block=%d, Hash=%x", newBlock.Header.Block, newBlock.Hash)
	return nil
}

// GetLatestBlock returns the head of the chain.
func (bc *Blockchain) GetLatestBlock() *types.Block {
	bc.lock.RLock()
	defer bc.lock.RUnlock()
	return bc.bestBlock
}

// GetBlockByHash returns a block given its hash.
func (bc *Blockchain) GetBlockByHash(hash []byte) (*types.Block, error) {
	bc.lock.RLock()
	defer bc.lock.RUnlock()
	block, ok := bc.blockIndex[string(hash)]
	if !ok {
		return nil, errors.New("block not found")
	}
	return block, nil
}

// GetBestBlockHash returns the hash of the active chain’s tip.
func (bc *Blockchain) GetBestBlockHash() []byte {
	bc.lock.RLock()
	defer bc.lock.RUnlock()
	return bc.bestBlock.Hash
}

// GetBlockCount returns the height of the active chain.
func (bc *Blockchain) GetBlockCount() int {
	bc.lock.RLock()
	defer bc.lock.RUnlock()
	return bc.bestBlock.Header.Block + 1
}

// GetBlocks returns the current blockchain.
func (bc *Blockchain) GetBlocks() []*types.Block {
	bc.lock.RLock()
	defer bc.lock.RUnlock()
	return bc.chain
}

// ChainLength returns the current length of the blockchain.
func (bc *Blockchain) ChainLength() int {
	bc.lock.RLock()
	defer bc.lock.RUnlock()
	return len(bc.chain)
}

// IsValidChain checks the integrity of the full chain.
func (bc *Blockchain) IsValidChain() error {
	bc.lock.RLock()
	defer bc.lock.RUnlock()

	for i := 1; i < len(bc.chain); i++ {
		prevBlock := bc.chain[i-1]
		currBlock := bc.chain[i]

		// Check previous hash linkage
		expectedPrevHash := prevBlock.GenerateBlockHash()
		if string(currBlock.Header.PrevHash) != string(expectedPrevHash) {
			return fmt.Errorf("block %d has invalid prev hash", currBlock.Header.Block)
		}

		// Check block sanity
		if err := currBlock.SanityCheck(); err != nil {
			return fmt.Errorf("block %d failed sanity: %w", currBlock.Header.Block, err)
		}
	}
	return nil
}
