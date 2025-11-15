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

// go/src/state/storage.go
package state

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	types "github.com/sphinx-core/go/src/core/transaction"
)

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

// NewStorage creates a new storage instance
func NewStorage(dataDir string) (*Storage, error) {
	storage := &Storage{
		dataDir:       dataDir,
		blocksDir:     filepath.Join(dataDir, "blocks"),
		indexDir:      filepath.Join(dataDir, "index"),
		stateDir:      filepath.Join(dataDir, "state"),
		blockIndex:    make(map[string]*types.Block),
		heightIndex:   make(map[uint64]*types.Block),
		txIndex:       make(map[string]*types.Transaction),
		totalBlocks:   0,
		bestBlockHash: "",
	}

	// Create directories if they don't exist
	if err := os.MkdirAll(storage.blocksDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create blocks directory: %w", err)
	}
	if err := os.MkdirAll(storage.indexDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create index directory: %w", err)
	}
	if err := os.MkdirAll(storage.stateDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create state directory: %w", err)
	}

	// Load existing data
	if err := storage.loadChainState(); err != nil {
		log.Printf("Warning: Could not load chain state: %v", err)
	}
	if err := storage.loadBlockIndex(); err != nil {
		log.Printf("Warning: Could not load block index: %v", err)
	}

	return storage, nil
}

// StoreBlock stores a block and updates indices
func (s *Storage) StoreBlock(block *types.Block) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	blockHash := block.GetHash()
	height := block.GetHeight()

	log.Printf("Storing block: height=%d, hash=%s", height, blockHash)

	// Check if block already exists
	if existing, exists := s.blockIndex[blockHash]; exists {
		if existing.GetHeight() == height {
			log.Printf("Block already exists: height=%d, hash=%s", height, blockHash)
			return nil // Block already stored
		}
	}

	// Store block to disk
	if err := s.storeBlockToDisk(block); err != nil {
		return fmt.Errorf("failed to store block to disk: %w", err)
	}

	// Update in-memory indices
	s.blockIndex[blockHash] = block
	s.heightIndex[height] = block

	// Update transaction index
	for _, tx := range block.Body.TxsList {
		if tx.ID != "" {
			s.txIndex[tx.ID] = tx
		}
	}

	// Update chain state if this is the new best block
	if height >= s.totalBlocks {
		s.bestBlockHash = blockHash
		s.totalBlocks = height + 1
		log.Printf("Updated best block: height=%d, hash=%s, total=%d",
			height, blockHash, s.totalBlocks)
	}

	// Persist updated indices
	if err := s.saveBlockIndex(); err != nil {
		return fmt.Errorf("failed to save block index: %w", err)
	}
	if err := s.saveChainState(); err != nil {
		return fmt.Errorf("failed to save chain state: %w", err)
	}

	log.Printf("Successfully stored block: height=%d, hash=%s", height, blockHash)
	return nil
}

// GetBlockByHash retrieves a block by its hash
func (s *Storage) GetBlockByHash(hash string) (*types.Block, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Try in-memory index first
	if block, exists := s.blockIndex[hash]; exists {
		return block, nil
	}

	// Fall back to disk
	block, err := s.loadBlockFromDisk(hash)
	if err != nil {
		return nil, fmt.Errorf("block not found: %w", err)
	}

	// Update in-memory index
	s.blockIndex[hash] = block
	s.heightIndex[block.GetHeight()] = block

	return block, nil
}

// GetBlockByHeight retrieves a block by its height
func (s *Storage) GetBlockByHeight(height uint64) (*types.Block, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Try in-memory index first
	if block, exists := s.heightIndex[height]; exists {
		return block, nil
	}

	// Need to search by height (this is less efficient)
	for _, block := range s.blockIndex {
		if block.GetHeight() == height {
			return block, nil
		}
	}

	return nil, fmt.Errorf("block at height %d not found", height)
}

// GetLatestBlock returns the latest block in the chain
func (s *Storage) GetLatestBlock() (*types.Block, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.bestBlockHash == "" {
		return nil, fmt.Errorf("no blocks in storage")
	}

	block, exists := s.blockIndex[s.bestBlockHash]
	if !exists {
		return nil, fmt.Errorf("best block not found in index: %s", s.bestBlockHash)
	}

	return block, nil
}

// GetTransaction retrieves a transaction by ID
func (s *Storage) GetTransaction(txID string) (*types.Transaction, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Try in-memory index first
	if tx, exists := s.txIndex[txID]; exists {
		return tx, nil
	}

	// Search through blocks (this is expensive, consider maintaining a separate tx index file)
	for _, block := range s.blockIndex {
		for _, tx := range block.Body.TxsList {
			if tx.ID == txID {
				s.txIndex[txID] = tx // Cache for future
				return tx, nil
			}
		}
	}

	return nil, fmt.Errorf("transaction %s not found", txID)
}

// GetTotalBlocks returns the total number of blocks stored
func (s *Storage) GetTotalBlocks() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.totalBlocks
}

// GetBestBlockHash returns the hash of the best block
func (s *Storage) GetBestBlockHash() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bestBlockHash
}

// ValidateChain validates the integrity of the stored chain
func (s *Storage) ValidateChain() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.totalBlocks == 0 {
		return nil
	}

	// Start from genesis and validate each block links to the previous
	var prevBlock *types.Block
	for height := uint64(0); height < s.totalBlocks; height++ {
		block, err := s.GetBlockByHeight(height)
		if err != nil {
			return fmt.Errorf("missing block at height %d: %w", height, err)
		}

		// Validate block structure
		if err := block.Validate(); err != nil {
			return fmt.Errorf("invalid block at height %d: %w", height, err)
		}

		// Validate chain linkage (except genesis)
		if height > 0 {
			if block.GetPrevHash() != prevBlock.GetHash() {
				return fmt.Errorf("chain broken at height %d", height)
			}
		}

		prevBlock = block
	}

	return nil
}

// Private methods

func (s *Storage) storeBlockToDisk(block *types.Block) error {
	blockHash := block.GetHash()
	filename := filepath.Join(s.blocksDir, blockHash+".json")

	data, err := json.MarshalIndent(block, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal block: %w", err)
	}

	// Write with atomic replace
	tmpFile := filename + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write block file: %w", err)
	}

	if err := os.Rename(tmpFile, filename); err != nil {
		return fmt.Errorf("failed to rename block file: %w", err)
	}

	log.Printf("Block written to disk: %s", filename)
	return nil
}

func (s *Storage) loadBlockFromDisk(hash string) (*types.Block, error) {
	filename := filepath.Join(s.blocksDir, hash+".json")

	// Check if file exists first
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return nil, fmt.Errorf("block file does not exist: %s", filename)
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read block file: %w", err)
	}

	var block types.Block
	if err := json.Unmarshal(data, &block); err != nil {
		return nil, fmt.Errorf("failed to unmarshal block: %w", err)
	}

	log.Printf("Block loaded from disk: height=%d, hash=%s", block.GetHeight(), block.GetHash())
	return &block, nil
}

func (s *Storage) saveBlockIndex() error {
	indexFile := filepath.Join(s.indexDir, "block_index.json")

	// Create a simplified index for persistence
	index := struct {
		Blocks map[string]uint64 `json:"blocks"` // hash -> height
	}{
		Blocks: make(map[string]uint64),
	}

	for hash, block := range s.blockIndex {
		index.Blocks[hash] = block.GetHeight()
	}

	data, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal block index: %w", err)
	}

	return os.WriteFile(indexFile, data, 0644)
}

func (s *Storage) loadBlockIndex() error {
	indexFile := filepath.Join(s.indexDir, "block_index.json")

	// Check if index file exists
	if _, err := os.Stat(indexFile); os.IsNotExist(err) {
		log.Printf("No block index file found, starting fresh")
		return nil // No index file yet
	}

	data, err := os.ReadFile(indexFile)
	if err != nil {
		return fmt.Errorf("failed to read block index: %w", err)
	}

	var index struct {
		Blocks map[string]uint64 `json:"blocks"`
	}
	if err := json.Unmarshal(data, &index); err != nil {
		return fmt.Errorf("failed to unmarshal block index: %w", err)
	}

	// Load blocks into memory index
	loadedCount := 0
	for hash, height := range index.Blocks {
		// Skip invalid entries
		if hash == "" {
			log.Printf("Warning: Skipping block with empty hash")
			continue
		}

		block, err := s.loadBlockFromDisk(hash)
		if err != nil {
			log.Printf("Warning: Could not load block %s: %v", hash, err)
			continue
		}
		s.blockIndex[hash] = block
		s.heightIndex[height] = block
		loadedCount++

		// Update chain state
		if height >= s.totalBlocks {
			s.totalBlocks = height + 1
			s.bestBlockHash = hash
		}
	}

	log.Printf("Loaded block index: %d blocks (from %d entries)", loadedCount, len(index.Blocks))

	// If we loaded blocks but no bestBlockHash was set, set it now
	if s.bestBlockHash == "" && loadedCount > 0 {
		// Find the block with highest height
		var maxHeight uint64
		var bestHash string
		for hash, block := range s.blockIndex {
			if block.GetHeight() >= maxHeight {
				maxHeight = block.GetHeight()
				bestHash = hash
			}
		}
		if bestHash != "" {
			s.bestBlockHash = bestHash
			s.totalBlocks = maxHeight + 1
			log.Printf("Auto-corrected chain state: bestBlock=%s, totalBlocks=%d",
				s.bestBlockHash, s.totalBlocks)
		}
	}

	return nil
}

func (s *Storage) saveChainState() error {
	stateFile := filepath.Join(s.stateDir, "chain_state.json")

	state := struct {
		BestBlockHash string `json:"best_block_hash"`
		TotalBlocks   uint64 `json:"total_blocks"`
	}{
		BestBlockHash: s.bestBlockHash,
		TotalBlocks:   s.totalBlocks,
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal chain state: %w", err)
	}

	return os.WriteFile(stateFile, data, 0644)
}

func (s *Storage) loadChainState() error {
	stateFile := filepath.Join(s.stateDir, "chain_state.json")

	// Check if state file exists
	if _, err := os.Stat(stateFile); os.IsNotExist(err) {
		log.Printf("No chain state file found, starting fresh")
		return nil // No state file yet
	}

	data, err := os.ReadFile(stateFile)
	if err != nil {
		return fmt.Errorf("failed to read chain state: %w", err)
	}

	var state struct {
		BestBlockHash string `json:"best_block_hash"`
		TotalBlocks   uint64 `json:"total_blocks"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("failed to unmarshal chain state: %w", err)
	}

	// CRITICAL FIX: Only set state if we have valid data
	if state.BestBlockHash == "" {
		log.Printf("Warning: Chain state has empty bestBlockHash, ignoring corrupted state")
		return fmt.Errorf("corrupted chain state: empty bestBlockHash")
	}

	s.bestBlockHash = state.BestBlockHash
	s.totalBlocks = state.TotalBlocks

	log.Printf("Loaded chain state: bestBlock=%s, totalBlocks=%d", s.bestBlockHash, s.totalBlocks)
	return nil
}

// Close performs cleanup operations
func (s *Storage) Close() error {
	// Save current state before closing
	if err := s.saveChainState(); err != nil {
		return fmt.Errorf("failed to save chain state on close: %w", err)
	}
	if err := s.saveBlockIndex(); err != nil {
		return fmt.Errorf("failed to save block index on close: %w", err)
	}
	return nil
}
