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

package core

import (
	"errors"
	"fmt"
	"sync"

	types "github.com/sphinx-core/go/src/core/transaction"
)

// Blockchain represents the core structure managing the active chain of blocks.
type Blockchain struct {
	chain      []*types.Block          // Active chain of blocks
	blockIndex map[string]*types.Block // Fast lookup for blocks by hash
	lock       sync.RWMutex
}

// NewBlockchain initializes a new blockchain with a genesis block.
func NewBlockchain(genesisBlock *types.Block) *Blockchain {
	bc := &Blockchain{
		chain:      []*types.Block{genesisBlock},
		blockIndex: make(map[string]*types.Block),
	}
	genesisHash := string(genesisBlock.GenerateBlockHash())
	bc.blockIndex[genesisHash] = genesisBlock
	return bc
}

// AddBlock adds a new block to the chain after validation.
func (bc *Blockchain) AddBlock(newBlock *types.Block) error {
	bc.lock.Lock()
	defer bc.lock.Unlock()

	if err := newBlock.SanityCheck(); err != nil {
		return fmt.Errorf("block failed sanity check: %w", err)
	}

	// Get the previous block
	prevBlock := bc.chain[len(bc.chain)-1]
	prevHash := string(prevBlock.GenerateBlockHash())

	// Check if the block links to the current head
	if string(newBlock.Header.PrevHash) != prevHash {
		return errors.New("block does not correctly reference previous block")
	}

	// All checks passed
	blockHash := string(newBlock.GenerateBlockHash())
	bc.chain = append(bc.chain, newBlock)
	bc.blockIndex[blockHash] = newBlock

	return nil
}

// GetLatestBlock returns the head of the chain.
func (bc *Blockchain) GetLatestBlock() *types.Block {
	bc.lock.RLock()
	defer bc.lock.RUnlock()
	return bc.chain[len(bc.chain)-1]
}

// GetBlockByHash returns a block given its hash.
func (bc *Blockchain) GetBlockByHash(hash []byte) (*types.Block, bool) {
	bc.lock.RLock()
	defer bc.lock.RUnlock()
	block, ok := bc.blockIndex[string(hash)]
	return block, ok
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
