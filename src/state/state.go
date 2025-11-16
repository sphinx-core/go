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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	types "github.com/sphinx-core/go/src/core/transaction"
)

// GetBlockByHeight returns a block by its height
func (s *Storage) GetBlockByHeight(height uint64) (*types.Block, error) {
	// Simple implementation - iterate through blocks to find by height
	// In production, you'd maintain a height index

	// Get all blocks (you'll need to implement this)
	blocks, err := s.GetAllBlocks()
	if err != nil {
		return nil, err
	}

	for _, block := range blocks {
		if block.GetHeight() == height {
			return block, nil
		}
	}

	return nil, fmt.Errorf("block at height %d not found", height)
}

// GetIndexDir returns the index directory path
func (s *Storage) GetIndexDir() string {
	return s.indexDir
}

// GetTransaction returns a transaction by ID
func (s *Storage) GetTransaction(txID string) (*types.Transaction, error) {
	// Search through all blocks for the transaction
	blocks, err := s.GetAllBlocks()
	if err != nil {
		return nil, err
	}

	for _, block := range blocks {
		for _, tx := range block.Body.TxsList {
			if tx.ID == txID {
				return tx, nil
			}
		}
	}

	return nil, fmt.Errorf("transaction %s not found", txID)
}

// GetAllBlocks returns all blocks in storage
func (s *Storage) GetAllBlocks() ([]*types.Block, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var blocks []*types.Block

	if s.totalBlocks == 0 {
		return blocks, nil // No blocks
	}

	// Iterate through height index to get all blocks in order
	for height := uint64(0); height < s.totalBlocks; height++ {
		block, exists := s.heightIndex[height]
		if !exists {
			// Try to load from disk
			// First, we need to find the hash for this height
			var blockHash string
			for hash, b := range s.blockIndex {
				if b.GetHeight() == height {
					blockHash = hash
					break
				}
			}
			if blockHash == "" {
				log.Printf("Warning: Missing block at height %d", height)
				continue
			}

			block, err := s.loadBlockFromDisk(blockHash)
			if err != nil {
				log.Printf("Warning: Could not load block at height %d: %v", height, err)
				continue
			}
			blocks = append(blocks, block)
		} else {
			blocks = append(blocks, block)
		}
	}

	return blocks, nil
}

// GetTotalBlocks returns the total number of blocks
func (s *Storage) GetTotalBlocks() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.totalBlocks
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

// SaveCompleteChainState saves the complete chain state including test results
// Now accepts chainParams to avoid import cycle
func (s *Storage) SaveCompleteChainState(chainState *ChainState, chainParams *ChainParams, walletPaths map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Set timestamp if not provided
	if chainState.Timestamp == "" {
		chainState.Timestamp = time.Now().Format(time.RFC3339)
	}

	// Add storage state information (basic chain state data)
	chainState.StorageState = &StorageState{
		BestBlockHash: s.bestBlockHash,
		TotalBlocks:   s.totalBlocks,
		BlocksDir:     s.blocksDir,
		IndexDir:      s.indexDir,
		StateDir:      s.stateDir,
	}

	// Add basic chain state directly to the main structure
	chainState.BasicChainState = &BasicChainState{
		BestBlockHash: s.bestBlockHash,
		TotalBlocks:   s.totalBlocks,
		LastUpdated:   time.Now().Format(time.RFC3339),
	}

	// CRITICAL FIX: Update ChainIdentification with actual genesis hash
	if chainParams != nil {
		// Update the genesis hash in ChainIdentification to use actual hash
		if chainState.ChainIdentification == nil {
			chainState.ChainIdentification = &ChainIdentification{
				Timestamp: time.Now().Format(time.RFC3339),
				ChainParams: map[string]interface{}{
					"chain_id":     chainParams.ChainID,
					"chain_name":   chainParams.ChainName,
					"symbol":       chainParams.Symbol,
					"genesis_time": chainParams.GenesisTime,
					"genesis_hash": chainParams.GenesisHash, // ACTUAL hash here
					"version":      chainParams.Version,
					"magic_number": chainParams.MagicNumber,
					"default_port": chainParams.DefaultPort,
					"bip44_type":   chainParams.BIP44CoinType,
				},
				TokenInfo: map[string]interface{}{
					"ledger_name": chainParams.LedgerName,
				},
				WalletPaths: walletPaths,
				NetworkInfo: map[string]interface{}{
					"network_name": "Sphinx Mainnet",
					"protocol":     "SPX/1.0.0",
				},
			}
		} else {
			// Update existing ChainIdentification with actual genesis hash
			if chainState.ChainIdentification.ChainParams == nil {
				chainState.ChainIdentification.ChainParams = make(map[string]interface{})
			}
			chainState.ChainIdentification.ChainParams["genesis_hash"] = chainParams.GenesisHash
			chainState.ChainIdentification.ChainParams["chain_id"] = chainParams.ChainID
			chainState.ChainIdentification.ChainParams["chain_name"] = chainParams.ChainName
			chainState.ChainIdentification.ChainParams["symbol"] = chainParams.Symbol
			chainState.ChainIdentification.ChainParams["genesis_time"] = chainParams.GenesisTime
			chainState.ChainIdentification.ChainParams["version"] = chainParams.Version
		}
	}

	// Save to chain_state.json in state directory
	stateFile := filepath.Join(s.stateDir, "chain_state.json")
	data, err := json.MarshalIndent(chainState, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal chain state: %w", err)
	}

	// Write with atomic replace
	tmpFile := stateFile + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write chain state file: %w", err)
	}

	if err := os.Rename(tmpFile, stateFile); err != nil {
		return fmt.Errorf("failed to rename chain state file: %w", err)
	}

	log.Printf("Complete chain state saved with actual genesis hash: %s", stateFile)
	return nil
}

// LoadCompleteChainState loads the complete chain state
func (s *Storage) LoadCompleteChainState() (*ChainState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stateFile := filepath.Join(s.stateDir, "chain_state.json")

	// Check if file exists
	if _, err := os.Stat(stateFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("chain state file does not exist: %s", stateFile)
	}

	data, err := os.ReadFile(stateFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read chain state file: %w", err)
	}

	var chainState ChainState
	if err := json.Unmarshal(data, &chainState); err != nil {
		return nil, fmt.Errorf("failed to unmarshal chain state: %w", err)
	}

	log.Printf("Complete chain state loaded from: %s", stateFile)
	return &chainState, nil
}

// GetChainStatePath returns the path to the chain state file
func (s *Storage) GetChainStatePath() string {
	return filepath.Join(s.stateDir, "chain_state.json")
}

// StoreBlock stores a block and updates indices with TxsRoot validation
func (s *Storage) StoreBlock(block *types.Block) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	blockHash := block.GetHash()
	height := block.GetHeight()

	log.Printf("Storing block: height=%d, hash=%s", height, blockHash)

	// Validate TxsRoot = MerkleRoot before storing
	if err := block.ValidateTxsRoot(); err != nil {
		return fmt.Errorf("block TxsRoot validation failed before storage: %w", err)
	}

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
		log.Printf("Updated best block: height=%d, hash=%s, total=%d, TxsRoot=%x",
			height, blockHash, s.totalBlocks, block.Header.TxsRoot)
	}

	// Persist updated indices
	if err := s.saveBlockIndex(); err != nil {
		return fmt.Errorf("failed to save block index: %w", err)
	}
	if err := s.saveChainState(); err != nil {
		return fmt.Errorf("failed to save chain state: %w", err)
	}

	log.Printf("Successfully stored block: height=%d, hash=%s, TxsRoot=%x (verified = MerkleRoot)",
		height, blockHash, block.Header.TxsRoot)
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

// Helper method to get actual genesis hash from block_index.json
func (s *Storage) GetGenesisHash() (string, error) {
	indexFile := filepath.Join(s.indexDir, "block_index.json")

	data, err := os.ReadFile(indexFile)
	if err != nil {
		return "", fmt.Errorf("failed to read block_index.json: %w", err)
	}

	var index struct {
		Blocks map[string]uint64 `json:"blocks"`
	}
	if err := json.Unmarshal(data, &index); err != nil {
		return "", fmt.Errorf("failed to unmarshal block_index.json: %w", err)
	}

	// Find the block with height 0 (genesis)
	for hash, height := range index.Blocks {
		if height == 0 {
			return hash, nil
		}
	}

	return "", fmt.Errorf("no genesis block found in block_index.json")
}

// FixChainStateGenesisHash updates any hardcoded genesis hash in chain_state.json with actual hash
func (s *Storage) FixChainStateGenesisHash() error {
	stateFile := filepath.Join(s.stateDir, "chain_state.json")

	// Check if file exists
	if _, err := os.Stat(stateFile); os.IsNotExist(err) {
		return nil // No chain state to fix
	}

	// Read existing chain state
	data, err := os.ReadFile(stateFile)
	if err != nil {
		return fmt.Errorf("failed to read chain state file: %w", err)
	}

	var chainState ChainState
	if err := json.Unmarshal(data, &chainState); err != nil {
		return fmt.Errorf("failed to unmarshal chain state: %w", err)
	}

	// Get actual genesis hash
	actualHash, err := s.GetGenesisHash()
	if err != nil {
		return fmt.Errorf("failed to get actual genesis hash: %w", err)
	}

	// Fix hardcoded genesis hash if found
	if chainState.ChainIdentification != nil && chainState.ChainIdentification.ChainParams != nil {
		if genesisHash, exists := chainState.ChainIdentification.ChainParams["genesis_hash"]; exists {
			if genesisHashStr, ok := genesisHash.(string); ok && genesisHashStr == "sphinx-genesis-2024" {
				chainState.ChainIdentification.ChainParams["genesis_hash"] = actualHash
				log.Printf("Fixed hardcoded genesis hash in chain_state.json: %s", actualHash)

				// Save the fixed chain state
				data, err := json.MarshalIndent(chainState, "", "  ")
				if err != nil {
					return fmt.Errorf("failed to marshal fixed chain state: %w", err)
				}

				tmpFile := stateFile + ".tmp"
				if err := os.WriteFile(tmpFile, data, 0644); err != nil {
					return fmt.Errorf("failed to write fixed chain state file: %w", err)
				}

				if err := os.Rename(tmpFile, stateFile); err != nil {
					return fmt.Errorf("failed to rename fixed chain state file: %w", err)
				}

				log.Printf("Successfully updated chain_state.json with actual genesis hash")
			}
		}
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

// saveChainState now saves basic chain state data directly to the main chain_state.json
func (s *Storage) saveChainState() error {
	stateFile := filepath.Join(s.stateDir, "chain_state.json")

	// Check if complete chain state already exists
	if _, err := os.Stat(stateFile); err == nil {
		// Complete chain state exists, update the basic chain state within it
		return s.updateBasicChainStateInFile(stateFile)
	}

	// No complete chain state exists, create a basic one
	basicState := &BasicChainState{
		BestBlockHash: s.bestBlockHash,
		TotalBlocks:   s.totalBlocks,
		LastUpdated:   time.Now().Format(time.RFC3339),
	}

	data, err := json.MarshalIndent(basicState, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal basic chain state: %w", err)
	}

	return os.WriteFile(stateFile, data, 0644)
}

// updateBasicChainStateInFile updates only the basic chain state portion of an existing chain_state.json
func (s *Storage) updateBasicChainStateInFile(stateFile string) error {
	// Read existing chain state
	data, err := os.ReadFile(stateFile)
	if err != nil {
		return fmt.Errorf("failed to read chain state file: %w", err)
	}

	var chainState ChainState
	if err := json.Unmarshal(data, &chainState); err != nil {
		// If it's not a ChainState, it might be a basic state file
		// In that case, we'll upgrade it to a complete chain state
		var basicState BasicChainState
		if err := json.Unmarshal(data, &basicState); err == nil {
			// Upgrade basic state to complete state
			chainState = ChainState{
				BasicChainState: &basicState,
				Timestamp:       time.Now().Format(time.RFC3339),
			}
		} else {
			return fmt.Errorf("failed to unmarshal chain state: %w", err)
		}
	}

	// Update basic chain state
	if chainState.BasicChainState == nil {
		chainState.BasicChainState = &BasicChainState{}
	}
	// ADD MERKLE ROOT INFORMATION TO NODES
	for _, node := range chainState.Nodes {
		if node != nil {
			// Get the block to calculate Merkle root
			block, err := s.GetBlockByHash(node.BlockHash)
			if err == nil && block != nil {
				merkleRoot := block.CalculateTxsRoot()
				node.MerkleRoot = hex.EncodeToString(merkleRoot)

				// Also update FinalState
				if node.FinalState != nil {
					node.FinalState.MerkleRoot = node.MerkleRoot
				}
			}
		}
	}
	chainState.BasicChainState.BestBlockHash = s.bestBlockHash
	chainState.BasicChainState.TotalBlocks = s.totalBlocks
	chainState.BasicChainState.LastUpdated = time.Now().Format(time.RFC3339)

	// Save updated chain state
	data, err = json.MarshalIndent(chainState, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal updated chain state: %w", err)
	}

	// Write with atomic replace
	tmpFile := stateFile + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write updated chain state file: %w", err)
	}

	if err := os.Rename(tmpFile, stateFile); err != nil {
		return fmt.Errorf("failed to rename updated chain state file: %w", err)
	}

	log.Printf("Updated basic chain state in: %s", stateFile)
	return nil
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

	// Try to load as complete chain state first
	var chainState ChainState
	if err := json.Unmarshal(data, &chainState); err == nil && chainState.BasicChainState != nil {
		// Successfully loaded complete chain state with basic data
		s.bestBlockHash = chainState.BasicChainState.BestBlockHash
		s.totalBlocks = chainState.BasicChainState.TotalBlocks
		log.Printf("Loaded chain state from complete file: bestBlock=%s, totalBlocks=%d", s.bestBlockHash, s.totalBlocks)
		return nil
	}

	// Fall back to basic chain state format
	var basicState BasicChainState
	if err := json.Unmarshal(data, &basicState); err != nil {
		return fmt.Errorf("failed to unmarshal chain state: %w", err)
	}

	// CRITICAL FIX: Only set state if we have valid data
	if basicState.BestBlockHash == "" {
		log.Printf("Warning: Chain state has empty bestBlockHash, ignoring corrupted state")
		return fmt.Errorf("corrupted chain state: empty bestBlockHash")
	}

	s.bestBlockHash = basicState.BestBlockHash
	s.totalBlocks = basicState.TotalBlocks

	log.Printf("Loaded basic chain state: bestBlock=%s, totalBlocks=%d", s.bestBlockHash, s.totalBlocks)
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

	// Remove old basic_chain_state.json if it exists
	basicStateFile := filepath.Join(s.stateDir, "basic_chain_state.json")
	if _, err := os.Stat(basicStateFile); err == nil {
		if err := os.Remove(basicStateFile); err != nil {
			log.Printf("Warning: Failed to remove old basic_chain_state.json on close: %v", err)
		}
	}

	return nil
}
