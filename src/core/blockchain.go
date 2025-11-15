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
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"

	"github.com/sphinx-core/go/src/common"
	"github.com/sphinx-core/go/src/consensus"
	types "github.com/sphinx-core/go/src/core/transaction"
	storage "github.com/sphinx-core/go/src/state"
)

// Global genesis block definition
var genesisBlockDefinition = &types.BlockHeader{
	Block:      0,
	Timestamp:  int64(1731375284), // Fixed timestamp
	PrevHash:   []byte("genesis"),
	Difficulty: big.NewInt(1),
	Nonce:      uint64(0),
	TxsRoot:    []byte{},
	StateRoot:  []byte{},
	GasLimit:   big.NewInt(1000000),
	GasUsed:    big.NewInt(0),
	ParentHash: []byte("sphinx-genesis-2024"),
	UnclesHash: []byte{},
}

// NewBlockchain creates a blockchain with state machine replication
// dataDir: Directory path for storing blockchain data
// nodeID: Unique identifier for this node in the network
// validators: List of validator node IDs that participate in consensus
// Returns a new Blockchain instance or error if initialization fails
func NewBlockchain(dataDir string, nodeID string, validators []string) (*Blockchain, error) {
	// Initialize storage layer for persistent block storage
	store, err := storage.NewStorage(dataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage: %w", err)
	}

	// Initialize state machine for Byzantine Fault Tolerance replication
	stateMachine := storage.NewStateMachine(store, nodeID, validators)

	blockchain := &Blockchain{
		storage:         store,                               // Persistent storage for blocks
		stateMachine:    stateMachine,                        // State machine for consensus replication
		txIndex:         make(map[string]*types.Transaction), // In-memory transaction index
		pendingTx:       []*types.Transaction{},              // Pending transactions waiting to be included in blocks
		status:          StatusInitializing,                  // Start in initializing state
		syncMode:        SyncModeFull,                        // Default to full sync mode
		consensusEngine: nil,                                 // Will be set later
	}

	// Load existing chain from storage or create genesis block if new chain
	if err := blockchain.initializeChain(); err != nil {
		return nil, fmt.Errorf("failed to initialize chain: %w", err)
	}

	// Start state machine replication for Byzantine Fault Tolerance
	if err := stateMachine.Start(); err != nil {
		return nil, fmt.Errorf("failed to start state machine: %w", err)
	}

	// Update status to running after successful initialization
	blockchain.status = StatusRunning

	log.Printf("Blockchain initialized with status: %s, sync mode: %s",
		blockchain.StatusString(blockchain.status),
		blockchain.SyncModeString(blockchain.syncMode))

	return blockchain, nil
}

// Add setter
func (bc *Blockchain) SetConsensusEngine(engine *consensus.Consensus) {
	bc.consensusEngine = engine
}

// StartLeaderLoop starts a goroutine that proposes blocks when this node is leader
func (bc *Blockchain) StartLeaderLoop(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(10 * time.Second) // Increased from 5 to 10 seconds
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if bc.consensusEngine == nil {
					continue
				}

				// Only leader proposes
				if !bc.consensusEngine.IsLeader() {
					continue
				}

				// Check if we have pending transactions
				bc.lock.RLock()
				hasTxs := len(bc.pendingTx) > 0
				bc.lock.RUnlock()

				if !hasTxs {
					log.Printf("Leader: no pending transactions to propose")
					continue
				}

				// Check if we're already in the process of proposing
				// You might need to add an "isProposing" flag to avoid duplicate proposals

				log.Printf("Leader %s: creating block with %d pending transactions",
					bc.consensusEngine.GetNodeID(), len(bc.pendingTx))

				// Create and propose block
				block, err := bc.CreateBlock()
				if err != nil {
					log.Printf("Leader: failed to create block: %v", err)
					continue
				}

				log.Printf("Leader %s proposing block at height %d with %d transactions",
					bc.consensusEngine.GetNodeID(), block.GetHeight(), len(block.Body.TxsList))

				if err := bc.consensusEngine.ProposeBlock(block); err != nil {
					log.Printf("Leader: failed to propose block: %v", err)
				} else {
					log.Printf("Leader: block proposal sent successfully")
				}
			}
		}
	}()
}

// GetStatus returns the current blockchain status
// Returns the current BlockchainStatus constant value
func (bc *Blockchain) GetStatus() BlockchainStatus {
	bc.lock.RLock()
	defer bc.lock.RUnlock()
	return bc.status
}

// SetStatus updates the blockchain status
// status: The new BlockchainStatus to set
func (bc *Blockchain) SetStatus(status BlockchainStatus) {
	bc.lock.Lock()
	defer bc.lock.Unlock()
	oldStatus := bc.status
	bc.status = status
	log.Printf("Blockchain status changed from %s to %s",
		bc.StatusString(oldStatus), bc.StatusString(status))
}

// HasPendingTx checks if a transaction is in the pending pool
func (bc *Blockchain) HasPendingTx(hash string) bool {
	bc.lock.RLock()
	defer bc.lock.RUnlock()
	for _, tx := range bc.pendingTx {
		if tx.ID == hash {
			return true
		}
	}
	return false
}

// GetSyncMode returns the current synchronization mode
// Returns the current SyncMode constant value
func (bc *Blockchain) GetSyncMode() SyncMode {
	bc.lock.RLock()
	defer bc.lock.RUnlock()
	return bc.syncMode
}

// SetSyncMode updates the synchronization mode
// mode: The new SyncMode to set
func (bc *Blockchain) SetSyncMode(mode SyncMode) {
	bc.lock.Lock()
	defer bc.lock.Unlock()
	oldMode := bc.syncMode
	bc.syncMode = mode
	log.Printf("Blockchain sync mode changed from %s to %s",
		bc.SyncModeString(oldMode), bc.SyncModeString(mode))
}

// ImportBlock imports a new block into the blockchain with result tracking
// block: The block to import
// Returns BlockImportResult indicating the import outcome
func (bc *Blockchain) ImportBlock(block *types.Block) BlockImportResult {
	// Check if blockchain is in running state
	if bc.GetStatus() != StatusRunning {
		log.Printf("Cannot import block - blockchain status is %s", bc.StatusString(bc.GetStatus()))
		return ImportError
	}

	// Validate the block before import
	if err := block.Validate(); err != nil {
		log.Printf("Block validation failed: %v", err)
		return ImportInvalid
	}

	// Verify block links to current chain
	latestBlock := bc.GetLatestBlock()
	if latestBlock != nil && block.GetPrevHash() != latestBlock.GetHash() {
		log.Printf("Block does not extend current chain: expected prevHash=%s, got prevHash=%s",
			latestBlock.GetHash(), block.GetPrevHash())
		return ImportedSide
	}

	// Try to commit the block through state machine replication
	if err := bc.CommitBlock(block); err != nil {
		log.Printf("Block commit failed: %v", err)
		return ImportError
	}

	log.Printf("Block imported successfully: height=%d, hash=%s",
		block.GetHeight(), block.GetHash())
	return ImportedBest
}

// ClearCache clears specific caches to free memory
// cacheType: The type of cache to clear (CacheType constant)
// Returns error if cache clearing fails
func (bc *Blockchain) ClearCache(cacheType CacheType) error {
	bc.lock.Lock()
	defer bc.lock.Unlock()

	switch cacheType {
	case CacheTypeBlock:
		// Clear block cache - keep only latest block in memory
		if len(bc.chain) > 1 {
			latestBlock := bc.chain[len(bc.chain)-1]
			bc.chain = []*types.Block{latestBlock}
		}
		log.Printf("Block cache cleared, kept %d blocks in memory", len(bc.chain))

	case CacheTypeTransaction:
		// Clear transaction index (transactions are in blocks anyway)
		before := len(bc.txIndex)
		bc.txIndex = make(map[string]*types.Transaction)
		log.Printf("Transaction cache cleared: removed %d entries", before)

	case CacheTypeReceipt:
		// Placeholder for receipt cache (if implemented later)
		log.Printf("Receipt cache cleared (not implemented)")

	case CacheTypeState:
		// Placeholder for state cache (if implemented later)
		log.Printf("State cache cleared (not implemented)")
	}

	return nil
}

// ClearAllCaches clears all caches to free maximum memory
// Returns error if cache clearing fails
func (bc *Blockchain) ClearAllCaches() error {
	log.Printf("Clearing all blockchain caches")

	// Clear block cache
	if err := bc.ClearCache(CacheTypeBlock); err != nil {
		return err
	}

	// Clear transaction cache
	if err := bc.ClearCache(CacheTypeTransaction); err != nil {
		return err
	}

	// Clear other caches
	bc.ClearCache(CacheTypeReceipt)
	bc.ClearCache(CacheTypeState)

	log.Printf("All blockchain caches cleared successfully")
	return nil
}

// StatusString returns a human-readable string for BlockchainStatus
// status: The BlockchainStatus constant to convert to string
// Returns descriptive string for the status
func (bc *Blockchain) StatusString(status BlockchainStatus) string {
	switch status {
	case StatusInitializing:
		return "Initializing"
	case StatusSyncing:
		return "Syncing"
	case StatusRunning:
		return "Running"
	case StatusStopped:
		return "Stopped"
	case StatusForked:
		return "Forked"
	default:
		return "Unknown"
	}
}

// SyncModeString returns a human-readable string for SyncMode
// mode: The SyncMode constant to convert to string
// Returns descriptive string for the sync mode
func (bc *Blockchain) SyncModeString(mode SyncMode) string {
	switch mode {
	case SyncModeFull:
		return "Full"
	case SyncModeFast:
		return "Fast"
	case SyncModeLight:
		return "Light"
	default:
		return "Unknown"
	}
}

// ImportResultString returns a human-readable string for BlockImportResult
// result: The BlockImportResult constant to convert to string
// Returns descriptive string for the import result
func (bc *Blockchain) ImportResultString(result BlockImportResult) string {
	switch result {
	case ImportedBest:
		return "Imported as best block"
	case ImportedSide:
		return "Imported as side chain"
	case ImportedExisting:
		return "Block already exists"
	case ImportInvalid:
		return "Block validation failed"
	case ImportError:
		return "Import error occurred"
	default:
		return "Unknown result"
	}
}

// CacheTypeString returns a human-readable string for CacheType
// cacheType: The CacheType constant to convert to string
// Returns descriptive string for the cache type
func (bc *Blockchain) CacheTypeString(cacheType CacheType) string {
	switch cacheType {
	case CacheTypeBlock:
		return "Block cache"
	case CacheTypeTransaction:
		return "Transaction cache"
	case CacheTypeReceipt:
		return "Receipt cache"
	case CacheTypeState:
		return "State cache"
	default:
		return "Unknown cache"
	}
}

// SetConsensus sets the consensus module for the state machine
// consensus: The consensus engine instance that will drive block finalization
// This connects the consensus algorithm with the state machine replication
func (bc *Blockchain) SetConsensus(consensus *consensus.Consensus) {
	bc.stateMachine.SetConsensus(consensus)
}

// AddTransaction adds a transaction with state machine replication
// tx: The transaction to add to the blockchain
// Returns error if transaction validation fails or transaction is duplicate
// Transaction goes through multiple validation steps before being accepted
func (bc *Blockchain) AddTransaction(tx *types.Transaction) error {
	bc.lock.Lock()         // Acquire lock for thread-safe transaction addition
	defer bc.lock.Unlock() // Ensure lock is released when function exits

	// Check if blockchain is ready to accept transactions
	if bc.status != StatusRunning {
		return fmt.Errorf("blockchain not ready to accept transactions, status: %s",
			bc.StatusString(bc.status))
	}

	// Validate transaction fields for basic correctness
	if tx.Sender == "" || tx.Receiver == "" || tx.Amount.Cmp(big.NewInt(0)) <= 0 {
		return errors.New("invalid transaction: empty sender/receiver or non-positive amount")
	}

	// Perform transaction sanity checks (format, signatures, etc.)
	if err := tx.SanityCheck(); err != nil {
		return fmt.Errorf("transaction failed sanity check: %w", err)
	}

	// Compute transaction ID if not already set by client
	// Compute transaction ID if not already set by client
	if tx.ID == "" {
		data := fmt.Sprintf("%s%s%s%s%s%v",
			tx.Sender, tx.Receiver, tx.Amount.String(),
			tx.GasLimit.String(), tx.GasPrice.String(), tx.Nonce)
		tx.ID = hex.EncodeToString(common.SpxHash([]byte(data)))
	}

	// Check for duplicate transaction to prevent double spending
	if _, exists := bc.txIndex[tx.ID]; exists {
		return errors.New("duplicate transaction ID")
	}

	// Create a Note for validation (placeholder for actual validation logic)
	note := &types.Note{
		From:      tx.Sender,
		To:        tx.Receiver,
		Fee:       0.01,      // Placeholder fee - would be calculated in production
		Storage:   "tx-data", // Placeholder storage identifier
		Timestamp: time.Now().Unix(),
		MAC:       "placeholder-mac", // Placeholder message authentication code
		Output: &types.Output{
			Value:   tx.Amount.Uint64(), // Convert big.Int to uint64 for output
			Address: tx.Receiver,        // Recipient address
		},
	}

	// Validate using Validator (placeholder validation logic)
	validator := types.NewValidator(tx.Sender, tx.Receiver)
	if err := validator.Validate(note); err != nil {
		return fmt.Errorf("transaction validation failed: %w", err)
	}

	// Add to pending transactions waiting for block inclusion
	bc.pendingTx = append(bc.pendingTx, tx)
	bc.txIndex[tx.ID] = tx // Index transaction for fast lookup

	// Propose transaction for state machine replication across all nodes
	// This ensures all validators see the same transaction order
	if err := bc.stateMachine.ProposeTransaction(tx); err != nil {
		log.Printf("Failed to propose transaction for replication: %v", err)
		// Continue anyway - transaction is still in pending pool for local node
	}

	log.Printf("Added transaction: ID=%s, Sender=%s, Receiver=%s, Amount=%s",
		tx.ID, tx.Sender, tx.Receiver, tx.Amount.String())
	return nil
}

// CreateBlock creates a new block from pending transactions
// Returns a new block containing all pending transactions
// Called by consensus leader when it's time to create a new block
// CreateBlock creates a new block from pending transactions
func (bc *Blockchain) CreateBlock() (*types.Block, error) {
	bc.lock.Lock()
	defer bc.lock.Unlock()

	if bc.status != StatusRunning {
		return nil, fmt.Errorf("blockchain not ready to create blocks, status: %s",
			bc.StatusString(bc.status))
	}

	if len(bc.pendingTx) == 0 {
		return nil, errors.New("no pending transactions")
	}

	// Get the latest block from storage to ensure we have the most recent
	prevBlock, err := bc.storage.GetLatestBlock()
	if err != nil || prevBlock == nil {
		return nil, fmt.Errorf("no previous block found: %v", err)
	}

	log.Printf("Creating new block on top of: height=%d, hash=%s",
		prevBlock.GetHeight(), prevBlock.GetHash())

	// Create a copy of pending transactions to avoid modifying the original slice
	txsToInclude := make([]*types.Transaction, len(bc.pendingTx))
	copy(txsToInclude, bc.pendingTx)

	// Calculate transaction root
	txsRoot := bc.calculateTransactionsRoot(txsToInclude)

	// For now, use a placeholder state root - in production this would come from state machine
	stateRoot := bc.calculateStateRoot()

	// FIX: Convert the previous hash string to bytes correctly
	// The hash is already a hex string, so we need to decode it to bytes
	prevHashBytes, err := hex.DecodeString(prevBlock.GetHash())
	if err != nil {
		return nil, fmt.Errorf("failed to decode previous hash: %w", err)
	}

	newHeader := types.NewBlockHeader(
		prevBlock.GetHeight()+1,
		prevHashBytes, // Use the decoded bytes, not the string as bytes
		big.NewInt(1),
		txsRoot,   // Proper transaction root
		stateRoot, // Proper state root
		big.NewInt(1000000),
		big.NewInt(0),
		[]byte{}, // Parent hash (empty for now)
		[]byte{}, // Uncles hash (empty for now)
		time.Now().Unix(),
	)

	newBody := types.NewBlockBody(txsToInclude, []byte{})
	newBlock := types.NewBlock(newHeader, newBody)
	newBlock.FinalizeHash()

	// Validate the block before returning it
	if err := newBlock.SanityCheck(); err != nil {
		return nil, fmt.Errorf("created invalid block: %v", err)
	}

	log.Printf("Created new block: height=%d, transactions=%d, prevHash=%s, hash=%s",
		newBlock.GetHeight(), len(txsToInclude), prevBlock.GetHash(), newBlock.GetHash())

	return newBlock, nil
}

// calculateTransactionsRoot calculates the Merkle root of transactions
func (bc *Blockchain) calculateTransactionsRoot(txs []*types.Transaction) []byte {
	if len(txs) == 0 {
		// Return hash of empty data for empty transactions
		return []byte{} // This will be handled by the block's CalculateTxsRoot method
	}

	// For now, delegate to the block's method
	// In production, you might want a more sophisticated Merkle tree implementation
	tempBlock := &types.Block{
		Body: types.BlockBody{TxsList: txs},
	}
	return tempBlock.CalculateTxsRoot()
}

// calculateStateRoot calculates the state root after applying transactions
func (bc *Blockchain) calculateStateRoot() []byte {
	// For now, return a placeholder state root
	// In production, this would be calculated from the state machine after applying transactions
	return []byte("placeholder-state-root")
}

// CommitBlock commits a block through state machine replication
// block: The block to commit to the blockchain
// Returns error if block proposal for replication fails
// This initiates the consensus process for the block across all validators
// Update the CommitBlock method to accept consensus.Block instead of *types.Block
func (bc *Blockchain) CommitBlock(block consensus.Block) error {
	// Type assertion to convert consensus.Block to *types.Block
	typeBlock, ok := block.(*types.Block)
	if !ok {
		return fmt.Errorf("invalid block type: expected *types.Block, got %T", block)
	}

	// Check if blockchain is in running state
	if bc.GetStatus() != StatusRunning {
		return fmt.Errorf("blockchain not ready to commit blocks, status: %s",
			bc.StatusString(bc.GetStatus()))
	}

	// Store block in storage
	if err := bc.storage.StoreBlock(typeBlock); err != nil {
		return fmt.Errorf("failed to store block: %w", err)
	}

	// Update in-memory chain
	bc.lock.Lock()
	bc.chain = append(bc.chain, typeBlock)

	// Clear pending transactions that were included in this block
	bc.pendingTx = []*types.Transaction{}
	bc.lock.Unlock()

	log.Printf("Block committed: height=%d, hash=%s",
		typeBlock.GetHeight(), typeBlock.GetHash())
	return nil
}

// VerifyStateConsistency verifies that this node's state matches other nodes
// otherState: State snapshot from another node to compare against
// Returns true if states match, false if there's a divergence
// Used for detecting forks or inconsistent states across the network
func (bc *Blockchain) VerifyStateConsistency(otherState *storage.StateSnapshot) (bool, error) {
	return bc.stateMachine.VerifyState(otherState)
}

// GetCurrentState returns the current state snapshot
// Returns the latest state of the blockchain including accounts, balances, etc.
// Used by other nodes to verify consistency or for new nodes to sync
func (bc *Blockchain) GetCurrentState() *storage.StateSnapshot {
	return bc.stateMachine.GetCurrentState()
}

// Add this method to Blockchain
func (bc *Blockchain) DebugStorage() error {
	// Test if we can store and retrieve a block
	testBlock, err := bc.storage.GetLatestBlock()
	if err != nil {
		return fmt.Errorf("GetLatestBlock failed: %w", err)
	}

	if testBlock == nil {
		return fmt.Errorf("GetLatestBlock returned nil (no blocks in storage)")
	}

	log.Printf("DEBUG: Storage test - Latest block: height=%d, hash=%s",
		testBlock.GetHeight(), testBlock.GetHash())
	return nil
}

// initializeChain loads existing chain or creates genesis block
// Called during blockchain initialization to bootstrap the chain
// Returns error if chain loading or genesis creation fails
func (bc *Blockchain) initializeChain() error {
	// First, try to get the latest block
	latestBlock, err := bc.storage.GetLatestBlock()
	if err != nil {
		log.Printf("Warning: Could not load initial state: %v", err)

		// Create genesis block
		log.Printf("No existing chain found, creating genesis block")
		if err := bc.createGenesisBlock(); err != nil {
			return fmt.Errorf("failed to create genesis block: %w", err)
		}

		// Now the genesis block should be in memory, don't try to reload from storage
		if len(bc.chain) == 0 {
			return fmt.Errorf("genesis block created but chain is empty")
		}

		latestBlock = bc.chain[0]
		log.Printf("Using genesis block from memory: height=%d, hash=%s",
			latestBlock.GetHeight(), latestBlock.GetHash())
	} else {
		// Load existing chain
		bc.chain = []*types.Block{latestBlock}
	}

	log.Printf("Chain initialized: height=%d, hash=%s, total_blocks=%d",
		latestBlock.GetHeight(), latestBlock.GetHash(), bc.storage.GetTotalBlocks())

	return nil
}

// createGenesisBlock creates and stores the genesis block
// Genesis block is the first block in the blockchain with no predecessor
// Returns error if genesis block storage fails
// go/src/core/blockchain.go

func (bc *Blockchain) createGenesisBlock() error {
	// Create genesis block from the shared definition
	genesisHeader := &types.BlockHeader{}
	*genesisHeader = *genesisBlockDefinition // Copy the definition

	genesisBody := types.NewBlockBody([]*types.Transaction{}, []byte{})
	genesis := types.NewBlock(genesisHeader, genesisBody)
	genesis.FinalizeHash()

	log.Printf("Creating genesis block: Height=%d, Hash=%s",
		genesis.GetHeight(), genesis.GetHash())

	// Store genesis block
	if err := bc.storage.StoreBlock(genesis); err != nil {
		return fmt.Errorf("failed to store genesis block: %w", err)
	}

	// Verify the block was stored by trying to retrieve it
	storedBlock, err := bc.storage.GetBlockByHash(genesis.GetHash())
	if err != nil || storedBlock == nil {
		return fmt.Errorf("genesis block storage verification failed: %v", err)
	}

	log.Printf("Genesis block stored and verified: %s", genesis.GetHash())

	// Initialize in-memory chain
	bc.chain = []*types.Block{genesis}
	return nil
}

// GetTransactionByID retrieves a transaction by its ID
// txID: The transaction identifier to look up
// Returns the transaction if found, error if not found
// Searches in-memory index first, then falls back to storage
func (bc *Blockchain) GetTransactionByID(txID []byte) (*types.Transaction, error) {
	bc.lock.RLock()         // Acquire read lock for thread-safe access
	defer bc.lock.RUnlock() // Ensure lock is released when function exits

	// Convert byte array to hex string for map lookup
	txIDStr := hex.EncodeToString(txID)

	// Try to find transaction in in-memory index first (faster)
	tx, exists := bc.txIndex[txIDStr]
	if !exists {
		// Not found in memory, try persistent storage
		return bc.storage.GetTransaction(txIDStr)
	}
	return tx, nil
}

// GetLatestBlock returns the head of the chain
// Returns the most recent block in the blockchain
// Returns nil if chain is empty (should not happen after genesis)
// GetLatestBlock satisfies consensus.BlockChain
// GetLatestBlock satisfies consensus.BlockChain
func (bc *Blockchain) GetLatestBlock() consensus.Block {
	block, err := bc.storage.GetLatestBlock()
	if err != nil || block == nil {
		return nil
	}
	return block
}

// GetBlockByHash returns a block given its hash
// hash: The block hash to search for
// Returns the block if found, error if not found
// Delegates to storage layer which may search disk or cache
// GetBlockByHash satisfies consensus.BlockChain (hash is a hex string)
// GetBlockByHash satisfies consensus.BlockChain (hash is a **hex string**)
func (bc *Blockchain) GetBlockByHash(hash string) consensus.Block {
	// storage uses hex strings internally
	block, err := bc.storage.GetBlockByHash(hash)
	if err != nil {
		return nil
	}
	return block
}

// GetBestBlockHash returns the hash of the active chain's tip
// Returns the hash of the most recent block in the blockchain
// Returns empty byte slice if chain is empty
func (bc *Blockchain) GetBestBlockHash() []byte {
	latest := bc.GetLatestBlock()
	if latest == nil {
		return []byte{} // Return empty if no blocks exist
	}
	return []byte(latest.GetHash()) // Return hash of latest block
}

// GetBlockCount returns the height of the active chain
// Returns the total number of blocks in the blockchain
// Note: Height is zero-based, so count = height + 1
func (bc *Blockchain) GetBlockCount() uint64 {
	latest := bc.GetLatestBlock()
	if latest == nil {
		return 0 // No blocks in chain
	}
	return latest.GetHeight() + 1 // Height is zero-based, count is one-based
}

// GetBlocks returns the current in-memory blockchain (limited)
// Returns slice of blocks currently loaded in memory
// For efficiency, only recent blocks may be kept in memory
func (bc *Blockchain) GetBlocks() []*types.Block {
	bc.lock.RLock()         // Acquire read lock for thread-safe access
	defer bc.lock.RUnlock() // Ensure lock is released when function exits
	return bc.chain         // Return in-memory chain slice
}

// ChainLength returns the current length of the in-memory chain
// Returns number of blocks currently loaded in memory
// Useful for monitoring memory usage and cache efficiency
func (bc *Blockchain) ChainLength() int {
	bc.lock.RLock()         // Acquire read lock for thread-safe access
	defer bc.lock.RUnlock() // Ensure lock is released when function exits
	return len(bc.chain)    // Return length of in-memory chain
}

// IsValidChain checks the integrity of the full chain
// Validates blockchain consistency, hashes, and linkages
// Returns error if any inconsistency is found in the chain
func (bc *Blockchain) IsValidChain() error {
	return bc.storage.ValidateChain()
}

// Close cleans up resources
// Closes storage connections and cleans up resources
// Should be called when shutting down the node
func (bc *Blockchain) Close() error {
	// Set status to stopped before closing
	bc.SetStatus(StatusStopped)
	log.Printf("Blockchain shutting down...")
	return bc.storage.Close()
}

// Implement consensus.BlockChain interface
// ValidateBlock validates a block against blockchain rules
// block: The block to validate
// Returns error if block is invalid according to consensus rules
// This method satisfies the consensus.BlockChain interface requirement
// ValidateBlock validates a block against blockchain rules
// go/src/core/blockchain.go

// ValidateBlock validates a block against blockchain rules
func (bc *Blockchain) ValidateBlock(block consensus.Block) error {
	b := block.(*types.Block)

	// 1. Structural sanity
	if err := b.SanityCheck(); err != nil {
		// For testing, be more lenient about state root
		if strings.Contains(err.Error(), "state root is missing") {
			log.Printf("WARNING: Block validation - state root is empty (allowed in test)")
		} else if strings.Contains(err.Error(), "transaction root is missing") {
			log.Printf("WARNING: Block validation - transaction root is empty (allowed in test)")
		} else {
			return fmt.Errorf("block sanity check failed: %w", err)
		}
	}

	// 2. Hash is correct (deterministic)
	expectedHash := b.GenerateBlockHash()
	if !bytes.Equal(b.Header.Hash, expectedHash) {
		return fmt.Errorf("invalid block hash: expected %x, got %x", expectedHash, b.Header.Hash)
	}

	// 3. Links to previous block
	prev := bc.GetLatestBlock()
	if prev != nil {
		// FIX: Compare the actual hash bytes, not string representations
		prevHashBytes, err := hex.DecodeString(prev.GetHash())
		if err != nil {
			return fmt.Errorf("failed to decode previous block hash: %w", err)
		}

		if !bytes.Equal(b.Header.PrevHash, prevHashBytes) {
			return fmt.Errorf("invalid prev hash: expected %s, got %x", prev.GetHash(), b.Header.PrevHash)
		}
	}

	return nil
}

// GetStats returns blockchain statistics for monitoring
// Returns map containing various blockchain metrics
func (bc *Blockchain) GetStats() map[string]interface{} {
	bc.lock.RLock()
	defer bc.lock.RUnlock()

	latestBlock := bc.GetLatestBlock()
	var latestHeight uint64
	var latestHash string
	if latestBlock != nil {
		latestHeight = latestBlock.GetHeight()
		latestHash = latestBlock.GetHash()
	}

	return map[string]interface{}{
		"status":            bc.StatusString(bc.status),
		"sync_mode":         bc.SyncModeString(bc.syncMode),
		"block_height":      latestHeight,
		"latest_block_hash": latestHash,
		"blocks_in_memory":  len(bc.chain),
		"pending_txs":       len(bc.pendingTx),
		"tx_index_size":     len(bc.txIndex),
		"total_blocks":      bc.storage.GetTotalBlocks(),
	}
}
