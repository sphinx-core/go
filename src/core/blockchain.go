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

// go/src/core/blockchain.go
package core

import (
	"errors"
	"fmt"
	"log"
	"math/big"
	"sync"
	"time"

	types "github.com/sphinx-core/go/src/core/transaction"
)

// Blockchain manages the chain of blocks.
type Blockchain struct {
	chain      []*types.Block
	blockIndex map[string]*types.Block
	pendingTx  []*types.Transaction
	bestChain  *types.Block
	lock       sync.RWMutex
}

// NewBlockchain creates a blockchain with a genesis block.
func NewBlockchain() *Blockchain {
	genesisHeader := types.NewBlockHeader(
		0, []byte{}, big.NewInt(1), []byte{}, []byte{}, big.NewInt(1000000), big.NewInt(0), []byte{}, []byte{},
	)
	genesisBody := types.NewBlockBody([]*types.Transaction{}, []byte{})
	genesis := types.NewBlock(genesisHeader, genesisBody)

	genesisHash := genesis.GenerateBlockHash()
	blockchain := &Blockchain{
		chain:      []*types.Block{genesis},
		blockIndex: map[string]*types.Block{string(genesisHash): genesis},
		pendingTx:  []*types.Transaction{},
		bestChain:  genesis,
	}
	log.Printf("Initialized blockchain with genesis block: Hash=%x", genesisHash)
	return blockchain
}

// AddTransaction adds a transaction to the pending list after validation.
func (blockchain *Blockchain) AddTransaction(tx *types.Transaction) error {
	blockchain.lock.Lock()
	defer blockchain.lock.Unlock()

	// Validate transaction fields
	if tx.Sender == "" || tx.Receiver == "" || tx.Amount.Cmp(big.NewInt(0)) <= 0 {
		return errors.New("invalid transaction: empty sender/receiver or non-positive amount")
	}
	if err := tx.SanityCheck(); err != nil {
		return fmt.Errorf("transaction failed sanity check: %w", err)
	}

	// Create a Note for validation
	note := &types.Note{
		From:      tx.Sender,
		To:        tx.Receiver,
		Fee:       0.01,      // Placeholder fee; adjust based on tx.Fee if available
		Storage:   "tx-data", // Placeholder; adjust as needed
		Timestamp: time.Now().Unix(),
		MAC:       "placeholder-mac", // Placeholder; compute actual MAC if needed
		Output: &types.Output{
			Value:   tx.Amount.Uint64(),
			Address: tx.Receiver,
		},
	}

	// Validate using Validator struct
	validator := types.NewValidator(tx.Sender, tx.Receiver)
	if err := validator.Validate(note); err != nil {
		return fmt.Errorf("transaction validation failed: %w", err)
	}

	blockchain.pendingTx = append(blockchain.pendingTx, tx)
	log.Printf("Added transaction: Sender=%s, Receiver=%s, Amount=%s", tx.Sender, tx.Receiver, tx.Amount.String())
	return nil
}

// AddBlock creates a new block from pending transactions.
func (blockchain *Blockchain) AddBlock() error {
	blockchain.lock.Lock()
	defer blockchain.lock.Unlock()

	if len(blockchain.pendingTx) == 0 {
		return errors.New("no pending transactions")
	}

	prevBlock := blockchain.bestChain
	newHeader := types.NewBlockHeader(
		prevBlock.Header.Block+1,
		prevBlock.GenerateBlockHash(),
		big.NewInt(1),
		[]byte{},
		[]byte{},
		big.NewInt(1000000),
		big.NewInt(0),
		[]byte{},
		[]byte{},
	)
	newBody := types.NewBlockBody(blockchain.pendingTx, []byte{})
	newBlock := types.NewBlock(newHeader, newBody)

	if err := newBlock.SanityCheck(); err != nil {
		return fmt.Errorf("block failed sanity check: %w", err)
	}
	if string(newBlock.Header.PrevHash) != string(prevBlock.GenerateBlockHash()) {
		return errors.New("block does not correctly reference previous block")
	}

	blockchain.chain = append(blockchain.chain, newBlock)
	blockchain.blockIndex[string(newBlock.GenerateBlockHash())] = newBlock
	blockchain.bestChain = newBlock
	blockchain.pendingTx = []*types.Transaction{}
	log.Printf("Added block to active chain: Block=%d, Hash=%x", newBlock.Header.Block, newBlock.GenerateBlockHash())
	return nil
}

// GetLatestBlock returns the head of the chain.
func (blockchain *Blockchain) GetLatestBlock() *types.Block {
	blockchain.lock.RLock()
	defer blockchain.lock.RUnlock()
	return blockchain.bestChain
}

// GetBlockByHash returns a block given its hash.
func (blockchain *Blockchain) GetBlockByHash(hash []byte) (*types.Block, error) {
	blockchain.lock.RLock()
	defer blockchain.lock.RUnlock()
	block, ok := blockchain.blockIndex[string(hash)]
	if !ok {
		return nil, errors.New("block not found")
	}
	return block, nil
}

// GetBestBlockHash returns the hash of the active chain’s tip.
func (blockchain *Blockchain) GetBestBlockHash() []byte {
	blockchain.lock.RLock()
	defer blockchain.lock.RUnlock()
	return blockchain.bestChain.GenerateBlockHash()
}

// GetBlockCount returns the height of the active chain.
func (blockchain *Blockchain) GetBlockCount() uint64 {
	blockchain.lock.RLock()
	defer blockchain.lock.RUnlock()
	return blockchain.bestChain.Header.Block + 1
}

// GetBlocks returns the current blockchain.
func (blockchain *Blockchain) GetBlocks() []*types.Block {
	blockchain.lock.RLock()
	defer blockchain.lock.RUnlock()
	return blockchain.chain
}

// ChainLength returns the current length of the blockchain.
func (blockchain *Blockchain) ChainLength() int {
	blockchain.lock.RLock()
	defer blockchain.lock.RUnlock()
	return len(blockchain.chain)
}

// IsValidChain checks the integrity of the full chain.
func (blockchain *Blockchain) IsValidChain() error {
	blockchain.lock.RLock()
	defer blockchain.lock.RUnlock()

	for i := 1; i < len(blockchain.chain); i++ {
		prevBlock := blockchain.chain[i-1]
		currBlock := blockchain.chain[i]

		if string(currBlock.Header.PrevHash) != string(prevBlock.GenerateBlockHash()) {
			return fmt.Errorf("block %d has invalid prev hash", currBlock.Header.Block)
		}

		if err := currBlock.SanityCheck(); err != nil {
			return fmt.Errorf("block %d failed sanity: %w", currBlock.Header.Block, err)
		}
	}
	return nil
}
