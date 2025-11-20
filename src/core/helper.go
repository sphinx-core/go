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

// go/src/core/helper.go
package core

import (
	"fmt"
	"math/big"

	"github.com/sphinx-core/go/src/consensus"
	types "github.com/sphinx-core/go/src/core/transaction"
	storage "github.com/sphinx-core/go/src/state"
)

// NewBlockHelper creates a new adapter for types.Block
func NewBlockHelper(block *types.Block) consensus.Block {
	return &BlockHelper{block: block}
}

// GetHeight returns the block height
func (a *BlockHelper) GetHeight() uint64 {
	return a.block.GetHeight()
}

// GetHash returns the block hash
func (a *BlockHelper) GetHash() string {
	return a.block.GetHash()
}

// GetPrevHash returns the previous block hash
func (a *BlockHelper) GetPrevHash() string {
	return a.block.GetPrevHash()
}

// GetTimestamp returns the block timestamp
func (a *BlockHelper) GetTimestamp() int64 {
	return a.block.GetTimestamp()
}

// Validate validates the block
func (a *BlockHelper) Validate() error {
	return a.block.Validate()
}

// GetDifficulty returns the block difficulty
func (a *BlockHelper) GetDifficulty() *big.Int {
	if a.block.Header != nil {
		return a.block.Header.Difficulty
	}
	return big.NewInt(1)
}

// GetUnderlyingBlock returns the underlying types.Block
func (a *BlockHelper) GetUnderlyingBlock() *types.Block {
	return a.block
}

// In core/block_helper.go or wherever BlockHelper is defined
func (b *BlockHelper) GetMerkleRoot() string {
	if b.block != nil && b.block.Header != nil {
		return fmt.Sprintf("%x", b.block.Header.TxsRoot)
	}
	return ""
}

func (b *BlockHelper) ExtractMerkleRoot() string {
	if b.block != nil && b.block.Header != nil {
		return fmt.Sprintf("%x", b.block.Header.TxsRoot)
	}
	return ""
}

// GetStateMachine returns the state machine instance
func (bc *Blockchain) GetStateMachine() *storage.StateMachine {
	bc.lock.RLock()
	defer bc.lock.RUnlock()
	return bc.stateMachine
}
