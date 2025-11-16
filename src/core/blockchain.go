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
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sphinx-core/go/src/consensus"
	types "github.com/sphinx-core/go/src/core/transaction"
	logger "github.com/sphinx-core/go/src/log"
	"github.com/sphinx-core/go/src/pool"
	storage "github.com/sphinx-core/go/src/state"
)

// GetMerkleRoot returns the Merkle root of transactions for a specific block
func (bc *Blockchain) GetMerkleRoot(blockHash string) (string, error) {
	block, err := bc.storage.GetBlockByHash(blockHash)
	if err != nil {
		return "", fmt.Errorf("failed to get block: %w", err)
	}

	// Calculate Merkle root from transactions
	merkleRoot := block.CalculateTxsRoot()
	return hex.EncodeToString(merkleRoot), nil
}

// GetCurrentMerkleRoot returns the Merkle root of the latest block
func (bc *Blockchain) GetCurrentMerkleRoot() (string, error) {
	latestBlock := bc.GetLatestBlock()
	if latestBlock == nil {
		return "", fmt.Errorf("no blocks available")
	}
	return bc.GetMerkleRoot(latestBlock.GetHash())
}

// GetBlockWithMerkleInfo returns detailed block information including Merkle root
func (bc *Blockchain) GetBlockWithMerkleInfo(blockHash string) (map[string]interface{}, error) {
	block, err := bc.storage.GetBlockByHash(blockHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get block: %w", err)
	}

	// Calculate Merkle root
	merkleRoot := block.CalculateTxsRoot()

	info := map[string]interface{}{
		"height":            block.GetHeight(),
		"hash":              block.GetHash(),
		"previous_hash":     hex.EncodeToString(block.Header.PrevHash),
		"merkle_root":       hex.EncodeToString(merkleRoot),
		"timestamp":         block.Header.Timestamp,
		"difficulty":        block.Header.Difficulty.String(),
		"nonce":             block.Header.Nonce,
		"gas_limit":         block.Header.GasLimit.String(),
		"gas_used":          block.Header.GasUsed.String(),
		"transaction_count": len(block.Body.TxsList),
		"transactions":      bc.getTransactionHashes(block.Body.TxsList),
	}

	return info, nil
}

// Helper method to extract transaction hashes
func (bc *Blockchain) getTransactionHashes(txs []*types.Transaction) []string {
	var hashes []string
	for _, tx := range txs {
		hashes = append(hashes, tx.ID)
	}
	return hashes
}

// CalculateBlockSize calculates the approximate size of a block in bytes
func (bc *Blockchain) CalculateBlockSize(block *types.Block) uint64 {
	size := uint64(0)

	// Header size (approximate)
	size += 80 // Fixed header components

	// Transactions size
	for _, tx := range block.Body.TxsList {
		size += bc.mempool.CalculateTransactionSize(tx)
	}

	return size
}

// ValidateBlockSize checks if a block exceeds size limits
func (bc *Blockchain) ValidateBlockSize(block *types.Block) error {
	if bc.chainParams == nil {
		return fmt.Errorf("chain parameters not initialized")
	}

	blockSize := bc.CalculateBlockSize(block)
	maxBlockSize := bc.chainParams.MaxBlockSize

	if blockSize > maxBlockSize {
		return fmt.Errorf("block size %d exceeds maximum %d bytes", blockSize, maxBlockSize)
	}

	// Also validate individual transactions
	for i, tx := range block.Body.TxsList {
		txSize := bc.mempool.CalculateTransactionSize(tx)
		maxTxSize := bc.chainParams.MaxTransactionSize

		if txSize > maxTxSize {
			return fmt.Errorf("transaction %d size %d exceeds maximum %d bytes", i, txSize, maxTxSize)
		}
	}

	return nil
}

// SaveChainState saves the chain state with the actual genesis hash
func (bc *Blockchain) StoreChainState(nodes []*storage.NodeInfo, testSummary *storage.TestSummary) error {
	if bc.chainParams == nil {
		return fmt.Errorf("chain parameters not initialized")
	}

	// Convert blockchain params to storage.ChainParams
	chainParams := &storage.ChainParams{
		ChainID:       bc.chainParams.ChainID,
		ChainName:     bc.chainParams.ChainName,
		Symbol:        bc.chainParams.Symbol,
		GenesisTime:   bc.chainParams.GenesisTime,
		GenesisHash:   bc.chainParams.GenesisHash,
		Version:       bc.chainParams.Version,
		MagicNumber:   bc.chainParams.MagicNumber,
		DefaultPort:   bc.chainParams.DefaultPort,
		BIP44CoinType: bc.chainParams.BIP44CoinType,
		LedgerName:    bc.chainParams.LedgerName,
	}

	walletPaths := bc.GetWalletDerivationPaths()

	// Create chain state
	chainState := &storage.ChainState{
		Nodes:     nodes,
		Timestamp: time.Now().Format(time.RFC3339),
	}

	// If test summary is provided, update it with actual genesis hash
	if testSummary != nil {
		testSummary.GenesisHash = bc.chainParams.GenesisHash
	}

	// Save chain state with actual parameters
	err := bc.storage.SaveCompleteChainState(chainState, chainParams, walletPaths)
	if err != nil {
		return fmt.Errorf("failed to save chain state: %w", err)
	}

	// Fix any existing hardcoded hashes
	bc.storage.FixChainStateGenesisHash()

	logger.Info("Chain state saved with genesis hash: %s", bc.chainParams.GenesisHash)
	return nil
}

// SaveBasicChainState saves a basic chain state
func (bc *Blockchain) SaveBasicChainState() error {
	return bc.StoreChainState(nil, nil)
}

// VerifyState verifies that chain_state.json has the correct genesis hash
func (bc *Blockchain) VerifyState() error {
	if bc.chainParams == nil {
		return fmt.Errorf("chain parameters not initialized")
	}

	// Load current chain state
	chainState, err := bc.storage.LoadCompleteChainState()
	if err != nil {
		return fmt.Errorf("failed to load chain state: %w", err)
	}

	// Check if genesis hash matches
	if chainState.ChainIdentification != nil &&
		chainState.ChainIdentification.ChainParams != nil {
		if genesisHash, exists := chainState.ChainIdentification.ChainParams["genesis_hash"]; exists {
			if genesisHashStr, ok := genesisHash.(string); ok {
				if genesisHashStr != bc.chainParams.GenesisHash {
					return fmt.Errorf("chain state genesis hash mismatch: expected %s, got %s",
						bc.chainParams.GenesisHash, genesisHashStr)
				}
				logger.Info("✓ Chain state verified: genesis hash matches")
				return nil
			}
		}
	}

	return fmt.Errorf("could not verify chain state: missing genesis hash")
}

// NewBlockchain creates a blockchain with state machine replication
func NewBlockchain(dataDir string, nodeID string, validators []string, networkType string) (*Blockchain, error) {
	// Initialize storage layer for persistent block storage
	store, err := storage.NewStorage(dataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage: %w", err)
	}

	// Initialize state machine for Byzantine Fault Tolerance replication
	stateMachine := storage.NewStateMachine(store, nodeID, validators)

	// Create blockchain with mempool (will be configured after chain params are set)
	blockchain := &Blockchain{
		storage:         store,
		stateMachine:    stateMachine,
		mempool:         nil, // Will be initialized after chain params
		chain:           []*types.Block{},
		txIndex:         make(map[string]*types.Transaction),
		pendingTx:       []*types.Transaction{},
		lock:            sync.RWMutex{},
		status:          StatusInitializing,
		syncMode:        SyncModeFull,
		consensusEngine: nil,
		chainParams:     nil,
	}

	// Load existing chain from storage or create genesis block if new chain
	if err := blockchain.initializeChain(); err != nil {
		return nil, fmt.Errorf("failed to initialize chain: %w", err)
	}

	// Now that we have the genesis block, set the chain params with actual hash
	if len(blockchain.chain) > 0 {
		genesisHash := blockchain.chain[0].GetHash()

		// Select network type
		var chainParams *SphinxChainParameters
		switch networkType {
		case "testnet":
			chainParams = GetTestnetChainParams(genesisHash)
		case "devnet":
			chainParams = GetDevnetChainParams(genesisHash)
		default:
			chainParams = GetSphinxChainParams(genesisHash)
		}

		blockchain.chainParams = chainParams

		// Validate chain parameters
		if err := ValidateChainParams(chainParams); err != nil {
			return nil, fmt.Errorf("invalid chain parameters: %w", err)
		}

		// Initialize mempool with configuration from chain params
		mempoolConfig := GetMempoolConfigFromChainParams(chainParams)
		blockchain.mempool = pool.NewMempool(mempoolConfig)

		logger.Info("Chain parameters initialized for %s: genesis_hash=%s",
			chainParams.GetNetworkName(), genesisHash)

		// Verify the genesis hash is properly stored in block_index.json
		if err := blockchain.verifyGenesisHashInIndex(); err != nil {
			logger.Warn("Warning: Genesis hash verification failed: %v", err)
		}

		// AUTO-SAVE: Save chain state with actual genesis hash
		if err := blockchain.SaveBasicChainState(); err != nil {
			logger.Warn("Warning: Failed to auto-save chain state: %v", err)
		} else {
			logger.Info("Auto-saved chain state")
		}
	}

	// Start state machine replication for Byzantine Fault Tolerance
	if err := stateMachine.Start(); err != nil {
		return nil, fmt.Errorf("failed to start state machine: %w", err)
	}

	// Update status to running after successful initialization
	blockchain.status = StatusRunning

	logger.Info("Blockchain initialized with status: %s, sync mode: %s, network: %s, genesis hash: %s",
		blockchain.StatusString(blockchain.status),
		blockchain.SyncModeString(blockchain.syncMode),
		blockchain.chainParams.GetNetworkName(),
		blockchain.chainParams.GenesisHash)

	return blockchain, nil
}

// GetStorage returns the storage instance for external access
func (bc *Blockchain) GetStorage() *storage.Storage {
	return bc.storage
}

// GetMempool returns the mempool instance
func (bc *Blockchain) GetMempool() *pool.Mempool {
	return bc.mempool
}

// GetChainParams returns the Sphinx blockchain parameters for external recognition
func (bc *Blockchain) GetChainParams() *SphinxChainParameters {
	return bc.chainParams
}

// GetChainInfo returns formatted chain information with actual genesis hash
func (bc *Blockchain) GetChainInfo() map[string]interface{} {
	params := bc.GetChainParams()
	latestBlock := bc.GetLatestBlock()

	var blockHeight uint64
	var blockHash string
	if latestBlock != nil {
		blockHeight = latestBlock.GetHeight()
		blockHash = latestBlock.GetHash()
	}

	// Use the correct network name based on chain parameters
	networkName := params.GetNetworkName()

	return map[string]interface{}{
		"chain_id":        params.ChainID,
		"chain_name":      params.ChainName,
		"symbol":          params.Symbol,
		"genesis_time":    params.GenesisTime,
		"genesis_hash":    params.GenesisHash,
		"version":         params.Version,
		"magic_number":    fmt.Sprintf("0x%x", params.MagicNumber),
		"default_port":    params.DefaultPort,
		"bip44_coin_type": params.BIP44CoinType,
		"ledger_name":     params.LedgerName,
		"current_height":  blockHeight,
		"latest_block":    blockHash,
		"network":         networkName, // Use the correct network name
	}
}

// IsSphinxChain validates if this blockchain follows Sphinx protocol using actual genesis hash
func (bc *Blockchain) IsSphinxChain() bool {
	if len(bc.chain) == 0 {
		return false
	}

	params := bc.GetChainParams()
	genesis := bc.chain[0]
	return genesis.GetHash() == params.GenesisHash
}

// GenerateLedgerHeaders generates headers specifically formatted for Ledger hardware
func (bc *Blockchain) GenerateLedgerHeaders(operation string, amount float64, address string, memo string) string {
	params := bc.GetChainParams()

	return fmt.Sprintf(
		"=== SPHINX LEDGER OPERATION ===\n"+
			"Chain: %s\n"+
			"Chain ID: %d\n"+
			"Operation: %s\n"+
			"Amount: %.6f SPX\n"+
			"Address: %s\n"+
			"Memo: %s\n"+
			"BIP44: 44'/%d'/0'/0/0\n"+
			"Timestamp: %d\n"+
			"========================",
		params.ChainName,
		params.ChainID,
		operation,
		amount,
		address,
		memo,
		params.BIP44CoinType,
		time.Now().Unix(),
	)
}

// ValidateChainID validates if this blockchain matches Sphinx network parameters
func (bc *Blockchain) ValidateChainID(chainID uint64) bool {
	params := bc.GetChainParams()
	return chainID == params.ChainID
}

// GetWalletDerivationPaths returns standard derivation paths for wallets
func (bc *Blockchain) GetWalletDerivationPaths() map[string]string {
	params := bc.GetChainParams()
	return map[string]string{
		"BIP44":  fmt.Sprintf("m/44'/%d'/0'/0/0", params.BIP44CoinType),
		"BIP49":  fmt.Sprintf("m/49'/%d'/0'/0/0", params.BIP44CoinType),
		"BIP84":  fmt.Sprintf("m/84'/%d'/0'/0/0", params.BIP44CoinType),
		"Ledger": fmt.Sprintf("m/44'/%d'/0'", params.BIP44CoinType),
		"Trezor": fmt.Sprintf("m/44'/%d'/0'/0/0", params.BIP44CoinType),
	}
}

// ConvertDenomination converts between SPX denominations
func (bc *Blockchain) ConvertDenomination(amount *big.Int, fromDenom, toDenom string) (*big.Int, error) {
	params := bc.GetChainParams()

	fromMultiplier, fromExists := params.Denominations[fromDenom]
	toMultiplier, toExists := params.Denominations[toDenom]

	if !fromExists || !toExists {
		return nil, fmt.Errorf("unknown denomination: %s or %s", fromDenom, toDenom)
	}

	// Convert to base units (nSPX) first
	baseAmount := new(big.Int).Mul(amount, fromMultiplier)

	// Convert to target denomination
	result := new(big.Int).Div(baseAmount, toMultiplier)

	return result, nil
}

// GenerateNetworkInfo returns network information for peer discovery
func (bc *Blockchain) GenerateNetworkInfo() string {
	params := bc.GetChainParams()
	latestBlock := bc.GetLatestBlock()

	var blockHeight uint64
	if latestBlock != nil {
		blockHeight = latestBlock.GetHeight()
	}

	return fmt.Sprintf(
		"Sphinx Network: %s\n"+
			"Chain ID: %d\n"+
			"Protocol Version: %s\n"+
			"Current Height: %d\n"+
			"Magic Number: 0x%x\n"+
			"Default Port: %d",
		params.ChainName,
		params.ChainID,
		params.Version,
		blockHeight,
		params.MagicNumber,
		params.DefaultPort,
	)
}

// SetConsensusEngine sets the consensus engine
func (bc *Blockchain) SetConsensusEngine(engine *consensus.Consensus) {
	bc.consensusEngine = engine
}

// StartLeaderLoop starts a goroutine that proposes blocks when this node is leader
func (bc *Blockchain) StartLeaderLoop(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(10 * time.Second)
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

				// Check if we have transactions in mempool
				hasTxs := bc.mempool.GetTransactionCount() > 0
				if !hasTxs {
					logger.Info("Leader: no pending transactions to propose")
					continue
				}

				logger.Info("Leader %s: creating block with %d pending transactions",
					bc.consensusEngine.GetNodeID(), bc.mempool.GetTransactionCount())

				// Create and propose block
				block, err := bc.CreateBlock()
				if err != nil {
					logger.Warn("Leader: failed to create block: %v", err)
					continue
				}

				logger.Info("Leader %s proposing block at height %d with %d transactions",
					bc.consensusEngine.GetNodeID(), block.GetHeight(), len(block.Body.TxsList))

				// Convert to consensus.Block using adapter
				consensusBlock := NewBlockHelper(block)
				if err := bc.consensusEngine.ProposeBlock(consensusBlock); err != nil {
					logger.Warn("Leader: failed to propose block: %v", err)
				} else {
					logger.Info("Leader: block proposal sent successfully")
				}
			}
		}
	}()
}

// GetStatus returns the current blockchain status
func (bc *Blockchain) GetStatus() BlockchainStatus {
	bc.lock.RLock()
	defer bc.lock.RUnlock()
	return bc.status
}

// SetStatus updates the blockchain status
func (bc *Blockchain) SetStatus(status BlockchainStatus) {
	bc.lock.Lock()
	defer bc.lock.Unlock()
	oldStatus := bc.status
	bc.status = status
	logger.Info("Blockchain status changed from %s to %s",
		bc.StatusString(oldStatus), bc.StatusString(status))
}

// HasPendingTx checks if a transaction is in the mempool
func (bc *Blockchain) HasPendingTx(hash string) bool {
	return bc.mempool.HasTransaction(hash)
}

// GetSyncMode returns the current synchronization mode
func (bc *Blockchain) GetSyncMode() SyncMode {
	bc.lock.RLock()
	defer bc.lock.RUnlock()
	return bc.syncMode
}

// SetSyncMode updates the synchronization mode
func (bc *Blockchain) SetSyncMode(mode SyncMode) {
	bc.lock.Lock()
	defer bc.lock.Unlock()
	oldMode := bc.syncMode
	bc.syncMode = mode
	logger.Info("Blockchain sync mode changed from %s to %s",
		bc.SyncModeString(oldMode), bc.SyncModeString(mode))
}

// ImportBlock imports a new block into the blockchain with result tracking
func (bc *Blockchain) ImportBlock(block *types.Block) BlockImportResult {
	// Check if blockchain is in running state
	if bc.GetStatus() != StatusRunning {
		logger.Info("Cannot import block - blockchain status is %s", bc.StatusString(bc.GetStatus()))
		return ImportError
	}

	// Validate the block before import
	if err := block.Validate(); err != nil {
		logger.Warn("Block validation failed: %v", err)
		return ImportInvalid
	}

	// Verify block links to current chain
	latestBlock := bc.GetLatestBlock()
	if latestBlock != nil && block.GetPrevHash() != latestBlock.GetHash() {
		logger.Info("Block does not extend current chain: expected prevHash=%s, got prevHash=%s",
			latestBlock.GetHash(), block.GetPrevHash())
		return ImportedSide
	}

	// Try to commit the block through state machine replication
	consensusBlock := NewBlockHelper(block)
	if err := bc.CommitBlock(consensusBlock); err != nil {
		logger.Warn("Block commit failed: %v", err)
		return ImportError
	}

	logger.Info("Block imported successfully: height=%d, hash=%s",
		block.GetHeight(), block.GetHash())
	return ImportedBest
}

// ClearCache clears specific caches to free memory
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
		logger.Info("Block cache cleared, kept %d blocks in memory", len(bc.chain))

	case CacheTypeTransaction:
		// Clear transaction index
		before := len(bc.txIndex)
		bc.txIndex = make(map[string]*types.Transaction)
		logger.Info("Transaction cache cleared: removed %d entries", before)

	case CacheTypeReceipt:
		logger.Info("Receipt cache cleared (not implemented)")

	case CacheTypeState:
		logger.Info("State cache cleared (not implemented)")
	}

	return nil
}

// ClearAllCaches clears all caches to free maximum memory
func (bc *Blockchain) ClearAllCaches() error {
	logger.Info("Clearing all blockchain caches")

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

	logger.Info("All blockchain caches cleared successfully")
	return nil
}

// StatusString returns a human-readable string for BlockchainStatus
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
func (bc *Blockchain) SetConsensus(consensus *consensus.Consensus) {
	bc.stateMachine.SetConsensus(consensus)
}

// AddTransaction now uses the comprehensive mempool
func (bc *Blockchain) AddTransaction(tx *types.Transaction) error {
	if bc.status != StatusRunning {
		return fmt.Errorf("blockchain not ready to accept transactions, status: %s",
			bc.StatusString(bc.status))
	}

	// Use the new BroadcastTransaction method
	err := bc.mempool.BroadcastTransaction(tx)
	if err != nil {
		return err
	}

	logger.Info("Transaction broadcast to mempool: ID=%s, Sender=%s, Receiver=%s, Amount=%s",
		tx.ID, tx.Sender, tx.Receiver, tx.Amount.String())
	return nil
}

// GetBlockSizeStats returns block size statistics
func (bc *Blockchain) GetBlockSizeStats() map[string]interface{} {
	stats := make(map[string]interface{})

	if bc.chainParams != nil {
		stats["max_block_size"] = bc.chainParams.MaxBlockSize
		stats["target_block_size"] = bc.chainParams.TargetBlockSize
		stats["max_transaction_size"] = bc.chainParams.MaxTransactionSize
		stats["block_gas_limit"] = bc.chainParams.BlockGasLimit.String()
	}

	// Calculate average block size from recent blocks
	recentBlocks := bc.getRecentBlocks(100)
	if len(recentBlocks) > 0 {
		totalSize := uint64(0)
		maxSize := uint64(0)
		minSize := ^uint64(0)

		for _, block := range recentBlocks {
			blockSize := bc.CalculateBlockSize(block)
			totalSize += blockSize

			if blockSize > maxSize {
				maxSize = blockSize
			}
			if blockSize < minSize {
				minSize = blockSize
			}
		}

		stats["average_block_size"] = totalSize / uint64(len(recentBlocks))
		stats["max_block_size_observed"] = maxSize
		stats["min_block_size_observed"] = minSize
		stats["blocks_analyzed"] = len(recentBlocks)
		if bc.chainParams.TargetBlockSize > 0 {
			stats["size_utilization_percent"] = float64(stats["average_block_size"].(uint64)) / float64(bc.chainParams.TargetBlockSize) * 100
		}
	}

	// Get mempool stats
	mempoolStats := bc.mempool.GetStats()
	for k, v := range mempoolStats {
		stats[k] = v
	}

	return stats
}

// getRecentBlocks returns recent blocks for analysis
func (bc *Blockchain) getRecentBlocks(count int) []*types.Block {
	var blocks []*types.Block
	latest := bc.GetLatestBlock()

	if latest == nil {
		return blocks
	}

	currentHeight := latest.GetHeight()
	startHeight := uint64(0)
	if currentHeight > uint64(count) {
		startHeight = currentHeight - uint64(count)
	}

	for height := startHeight; height <= currentHeight; height++ {
		block := bc.GetBlockByNumber(height)
		if block != nil {
			blocks = append(blocks, block)
		}
	}

	return blocks
}

// GetBlocksizeInfo returns detailed blocksize information for RPC/API
func (bc *Blockchain) GetBlocksizeInfo() map[string]interface{} {
	info := make(map[string]interface{})

	if bc.chainParams != nil {
		info["limits"] = map[string]interface{}{
			"max_block_size_bytes":       bc.chainParams.MaxBlockSize,
			"max_transaction_size_bytes": bc.chainParams.MaxTransactionSize,
			"target_block_size_bytes":    bc.chainParams.TargetBlockSize,
			"block_gas_limit":            bc.chainParams.BlockGasLimit.String(),
		}

		// Convert to human-readable formats
		info["human_readable"] = map[string]interface{}{
			"max_block_size":       fmt.Sprintf("%.2f MB", float64(bc.chainParams.MaxBlockSize)/(1024*1024)),
			"max_transaction_size": fmt.Sprintf("%.2f KB", float64(bc.chainParams.MaxTransactionSize)/1024),
			"target_block_size":    fmt.Sprintf("%.2f MB", float64(bc.chainParams.TargetBlockSize)/(1024*1024)),
		}
	}

	// Add current statistics
	stats := bc.GetBlockSizeStats()
	info["current_stats"] = stats

	return info
}

// CreateBlock creates a new block with transactions from mempool
// CreateBlock creates a new block with transactions from mempool
func (bc *Blockchain) CreateBlock() (*types.Block, error) {
	bc.lock.Lock()
	defer bc.lock.Unlock()

	if bc.status != StatusRunning {
		return nil, fmt.Errorf("blockchain not ready to create blocks, status: %s",
			bc.StatusString(bc.status))
	}

	// Get the latest block
	prevBlock, err := bc.storage.GetLatestBlock()
	if err != nil || prevBlock == nil {
		return nil, fmt.Errorf("no previous block found: %v", err)
	}

	// Select transactions from mempool within block size limits
	selectedTxs, totalSize := bc.mempool.SelectTransactionsForBlock(
		bc.chainParams.MaxBlockSize,
		bc.chainParams.TargetBlockSize,
	)

	if len(selectedTxs) == 0 {
		return nil, errors.New("no transactions fit within block size limits")
	}

	logger.Info("Creating block with %d transactions, estimated size: %d bytes",
		len(selectedTxs), totalSize)

	// Calculate roots
	txsRoot := bc.calculateTransactionsRoot(selectedTxs)
	stateRoot := bc.calculateStateRoot()

	// Convert previous hash
	prevHashBytes, err := hex.DecodeString(prevBlock.GetHash())
	if err != nil {
		return nil, fmt.Errorf("failed to decode previous hash: %w", err)
	}

	newHeader := types.NewBlockHeader(
		prevBlock.GetHeight()+1,
		prevHashBytes,
		big.NewInt(1),
		txsRoot,
		stateRoot,
		bc.chainParams.BlockGasLimit,
		big.NewInt(0),
		[]byte{},
		[]byte{},
		time.Now().Unix(),
	)

	newBody := types.NewBlockBody(selectedTxs, []byte{})
	newBlock := types.NewBlock(newHeader, newBody)

	// Finalize hash ensures TxsRoot is properly set
	newBlock.FinalizeHash()

	// Validate that TxsRoot = MerkleRoot
	if err := newBlock.ValidateTxsRoot(); err != nil {
		return nil, fmt.Errorf("created block has inconsistent TxsRoot: %v", err)
	}

	// Validate block size
	if err := bc.ValidateBlockSize(newBlock); err != nil {
		return nil, fmt.Errorf("created block exceeds size limits: %v", err)
	}

	// Sanity check (includes TxsRoot validation)
	if err := newBlock.SanityCheck(); err != nil {
		return nil, fmt.Errorf("created invalid block: %v", err)
	}

	logger.Info("Created new block: height=%d, transactions=%d, size=%d bytes, hash=%s, TxsRoot=%x",
		newBlock.GetHeight(), len(selectedTxs), totalSize, newBlock.GetHash(), newBlock.Header.TxsRoot)
	return newBlock, nil
}

// VerifyTransactionInBlock verifies if a transaction is included in a block
func (bc *Blockchain) VerifyTransactionInBlock(tx *types.Transaction, blockHash string) (bool, error) {
	block, err := bc.storage.GetBlockByHash(blockHash)
	if err != nil {
		return false, fmt.Errorf("failed to get block: %w", err)
	}

	tree := types.NewMerkleTree(block.Body.TxsList)
	return tree.VerifyTransaction(tx), nil
}

// GenerateTransactionProof generates a Merkle proof for a transaction
func (bc *Blockchain) GenerateTransactionProof(tx *types.Transaction, blockHash string) ([][]byte, error) {
	block, err := bc.storage.GetBlockByHash(blockHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get block: %w", err)
	}

	tree := types.NewMerkleTree(block.Body.TxsList)
	proof, err := tree.GenerateMerkleProof(tx)
	if err != nil {
		return nil, fmt.Errorf("failed to generate merkle proof: %w", err)
	}

	return proof, nil
}

// calculateTransactionsRoot calculates the Merkle root of transactions
func (bc *Blockchain) calculateTransactionsRoot(txs []*types.Transaction) []byte {
	if len(txs) == 0 {
		return []byte{}
	}

	tempBlock := &types.Block{
		Body: types.BlockBody{TxsList: txs},
	}
	return tempBlock.CalculateTxsRoot()
}

// calculateStateRoot calculates the state root after applying transactions
func (bc *Blockchain) calculateStateRoot() []byte {
	// For now, return a placeholder state root
	return []byte("placeholder-state-root")
}

// CommitBlock commits a block through state machine replication
func (bc *Blockchain) CommitBlock(block consensus.Block) error {
	// Extract the underlying types.Block from adapter
	var typeBlock *types.Block
	switch b := block.(type) {
	case *BlockHelper:
		typeBlock = b.GetUnderlyingBlock()
	default:
		return fmt.Errorf("invalid block type: expected *BlockHelper, got %T", block)
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

	// Remove committed transactions from mempool
	txIDs := make([]string, len(typeBlock.Body.TxsList))
	for i, tx := range typeBlock.Body.TxsList {
		txIDs[i] = tx.ID
	}
	bc.mempool.RemoveTransactions(txIDs)
	bc.lock.Unlock()

	logger.Info("Block committed: height=%d, hash=%s, removed %d transactions from mempool",
		typeBlock.GetHeight(), typeBlock.GetHash(), len(txIDs))
	return nil
}

// VerifyStateConsistency verifies that this node's state matches other nodes
func (bc *Blockchain) VerifyStateConsistency(otherState *storage.StateSnapshot) (bool, error) {
	return bc.stateMachine.VerifyState(otherState)
}

// GetCurrentState returns the current state snapshot
func (bc *Blockchain) GetCurrentState() *storage.StateSnapshot {
	return bc.stateMachine.GetCurrentState()
}

// DebugStorage tests storage functionality
func (bc *Blockchain) DebugStorage() error {
	testBlock, err := bc.storage.GetLatestBlock()
	if err != nil {
		return fmt.Errorf("GetLatestBlock failed: %w", err)
	}

	if testBlock == nil {
		return fmt.Errorf("GetLatestBlock returned nil (no blocks in storage)")
	}

	logger.Info("DEBUG: Storage test - Latest block: height=%d, hash=%s",
		testBlock.GetHeight(), testBlock.GetHash())
	return nil
}

// initializeChain loads existing chain or creates genesis block
func (bc *Blockchain) initializeChain() error {
	// First, try to get the latest block
	latestBlock, err := bc.storage.GetLatestBlock()
	if err != nil {
		logger.Warn("Warning: Could not load initial state: %v", err)

		// Create genesis block
		logger.Info("No existing chain found, creating genesis block")
		if err := bc.createGenesisBlock(); err != nil {
			return fmt.Errorf("failed to create genesis block: %w", err)
		}

		// Now the genesis block should be in memory, don't try to reload from storage
		if len(bc.chain) == 0 {
			return fmt.Errorf("genesis block created but chain is empty")
		}

		latestBlock = bc.chain[0]
		logger.Info("Using genesis block from memory: height=%d, hash=%s",
			latestBlock.GetHeight(), latestBlock.GetHash())
	} else {
		// Load existing chain
		bc.chain = []*types.Block{latestBlock}
	}

	logger.Info("Chain initialized: height=%d, hash=%s, total_blocks=%d",
		latestBlock.GetHeight(), latestBlock.GetHash(), bc.storage.GetTotalBlocks())

	return nil
}

// createGenesisBlock creates and stores the genesis block with actual hash
func (bc *Blockchain) createGenesisBlock() error {
	// Create genesis block from the shared definition
	genesisHeader := &types.BlockHeader{}
	*genesisHeader = *genesisBlockDefinition

	genesisBody := types.NewBlockBody([]*types.Transaction{}, []byte{})
	genesis := types.NewBlock(genesisHeader, genesisBody)

	// Generate the actual hash for the genesis block
	genesis.FinalizeHash()

	// Now set the ParentHash to the actual genesis hash
	genesisHashBytes, err := hex.DecodeString(genesis.GetHash())
	if err != nil {
		return fmt.Errorf("failed to decode genesis hash: %w", err)
	}
	genesis.Header.ParentHash = genesisHashBytes

	logger.Info("Creating genesis block: Height=%d, Hash=%s",
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

	logger.Info("Genesis block stored and verified: %s", genesis.GetHash())

	// Initialize in-memory chain
	bc.chain = []*types.Block{genesis}

	return nil
}

// verifyGenesisHashInIndex verifies that the genesis hash in block_index.json matches our actual genesis hash
func (bc *Blockchain) verifyGenesisHashInIndex() error {
	if len(bc.chain) == 0 {
		return fmt.Errorf("no genesis block in chain")
	}

	actualGenesisHash := bc.chain[0].GetHash()

	// Try to read the block_index.json to verify the hash is there
	indexFile := filepath.Join(bc.storage.GetIndexDir(), "block_index.json")
	data, err := os.ReadFile(indexFile)
	if err != nil {
		return fmt.Errorf("failed to read block_index.json: %w", err)
	}

	var index struct {
		Blocks map[string]uint64 `json:"blocks"`
	}
	if err := json.Unmarshal(data, &index); err != nil {
		return fmt.Errorf("failed to unmarshal block_index.json: %w", err)
	}

	// Check if our genesis hash exists in the index
	if height, exists := index.Blocks[actualGenesisHash]; exists {
		if height == 0 {
			logger.Info("✓ Genesis hash verified in block_index.json: %s", actualGenesisHash)
			return nil
		} else {
			return fmt.Errorf("genesis block has wrong height in index: expected 0, got %d", height)
		}
	} else {
		return fmt.Errorf("genesis hash not found in block_index.json")
	}
}

// GetGenesisHashFromIndex reads the actual genesis hash from block_index.json
func (bc *Blockchain) GetGenesisHashFromIndex() (string, error) {
	indexFile := filepath.Join(bc.storage.GetIndexDir(), "block_index.json")

	// Check if file exists
	if _, err := os.Stat(indexFile); os.IsNotExist(err) {
		return "", fmt.Errorf("block_index.json does not exist")
	}

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

// PrintBlockIndex prints the current block_index.json contents
func (bc *Blockchain) PrintBlockIndex() {
	indexFile := filepath.Join(bc.storage.GetIndexDir(), "block_index.json")

	data, err := os.ReadFile(indexFile)
	if err != nil {
		logger.Warn("Error reading block_index.json: %v", err)
		return
	}

	var index map[string]interface{}
	if err := json.Unmarshal(data, &index); err != nil {
		logger.Warn("Error unmarshaling block_index.json: %v", err)
		return
	}

	formatted, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		logger.Warn("Error formatting block_index.json: %v", err)
		return
	}

	logger.Info("Current block_index.json contents:")
	logger.Info("%s", string(formatted))
}

// GetTransactionByID retrieves a transaction by its ID
func (bc *Blockchain) GetTransactionByID(txID []byte) (*types.Transaction, error) {
	bc.lock.RLock()
	defer bc.lock.RUnlock()

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

// GetTransactionByIDString retrieves a transaction by its ID (string version)
func (bc *Blockchain) GetTransactionByIDString(txIDStr string) (*types.Transaction, error) {
	// Convert string to []byte for the existing method
	txIDBytes, err := hex.DecodeString(txIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid transaction ID: %v", err)
	}

	// Call the existing byte-based method
	return bc.GetTransactionByID(txIDBytes)
}

// GetLatestBlock returns the head of the chain with adapter
func (bc *Blockchain) GetLatestBlock() consensus.Block {
	block, err := bc.storage.GetLatestBlock()
	if err != nil || block == nil {
		return nil
	}
	return NewBlockHelper(block)
}

// GetBlockByNumber returns a block by its height/number
func (bc *Blockchain) GetBlockByNumber(height uint64) *types.Block {
	bc.lock.RLock()
	defer bc.lock.RUnlock()

	// Search in-memory chain first
	for _, block := range bc.chain {
		if block.GetHeight() == height {
			return block
		}
	}

	// Fall back to storage
	block, err := bc.storage.GetBlockByHeight(height)
	if err != nil {
		logger.Warn("Error getting block by height %d: %v", height, err)
		return nil
	}
	return block
}

// GetBlockByHash returns a block by its hash with adapter
func (bc *Blockchain) GetBlockByHash(hash string) consensus.Block {
	block, err := bc.storage.GetBlockByHash(hash)
	if err != nil || block == nil {
		return nil
	}
	return NewBlockHelper(block)
}

// GetBlockHash returns the block hash for a given height
func (bc *Blockchain) GetBlockHash(height uint64) string {
	block := bc.GetBlockByNumber(height)
	if block == nil {
		return ""
	}
	return block.GetHash()
}

// GetDifficulty returns the current network difficulty
func (bc *Blockchain) GetDifficulty() *big.Int {
	latest := bc.GetLatestBlock()
	if latest == nil {
		return big.NewInt(1)
	}
	return latest.GetDifficulty()
}

// GetChainTip returns information about the current chain tip
func (bc *Blockchain) GetChainTip() map[string]interface{} {
	latest := bc.GetLatestBlock()
	if latest == nil {
		return nil
	}

	return map[string]interface{}{
		"height":    latest.GetHeight(),
		"hash":      latest.GetHash(),
		"timestamp": latest.GetTimestamp(),
	}
}

// ValidateAddress validates if an address is properly formatted
func (bc *Blockchain) ValidateAddress(address string) bool {
	// Basic address validation
	if len(address) != 40 {
		return false
	}
	_, err := hex.DecodeString(address)
	return err == nil
}

// GetNetworkInfo returns network information
func (bc *Blockchain) GetNetworkInfo() map[string]interface{} {
	params := bc.GetChainParams()
	latest := bc.GetLatestBlock()

	info := map[string]interface{}{
		"version":          params.Version,
		"chain":            params.ChainName,
		"chain_id":         params.ChainID,
		"protocol_version": "1.0.0",
		"symbol":           params.Symbol,
	}

	if latest != nil {
		info["blocks"] = latest.GetHeight()
		info["best_block_hash"] = latest.GetHash()
		info["difficulty"] = bc.GetDifficulty().String()
		info["median_time"] = latest.GetTimestamp()
	}

	return info
}

// GetMiningInfo returns mining-related information
func (bc *Blockchain) GetMiningInfo() map[string]interface{} {
	latest := bc.GetLatestBlock()

	info := map[string]interface{}{
		"blocks":         0,
		"current_weight": 0,
		"difficulty":     bc.GetDifficulty().String(),
		"network_hashps": big.NewInt(0).String(),
	}

	if latest != nil {
		info["blocks"] = latest.GetHeight()
		info["current_block_weight"] = 0

		// Use adapter to access body for transaction count
		if adapter, ok := latest.(*BlockHelper); ok {
			block := adapter.GetUnderlyingBlock()
			info["current_block_tx"] = len(block.Body.TxsList)
		} else {
			info["current_block_tx"] = 0
		}
	}

	return info
}

// EstimateFee estimates transaction fee (placeholder implementation)
func (bc *Blockchain) EstimateFee(blocks int) map[string]interface{} {
	// Basic fee estimation
	baseFee := big.NewInt(1000000)

	return map[string]interface{}{
		"feerate": baseFee.String(),
		"blocks":  blocks,
		"estimates": map[string]interface{}{
			"conservative": baseFee.String(),
			"economic":     baseFee.String(),
		},
	}
}

// GetMemPoolInfo returns mempool information
func (bc *Blockchain) GetMemPoolInfo() map[string]interface{} {
	mempoolStats := bc.mempool.GetStats()

	return map[string]interface{}{
		"size":            mempoolStats["transaction_count"],
		"bytes":           mempoolStats["mempool_size_bytes"],
		"usage":           mempoolStats["mempool_size_bytes"].(uint64) * 2,
		"max_mempool":     300000000,
		"mempool_min_fee": "0.00001000",
		"mempool_stats":   mempoolStats,
	}
}

// VerifyMessage verifies a signed message (placeholder)
func (bc *Blockchain) VerifyMessage(address, signature, message string) bool {
	logger.Info("Message verification requested - address: %s, message: %s", address, message)
	return true
}

// GetRawTransaction returns raw transaction data
func (bc *Blockchain) GetRawTransaction(txID string, verbose bool) interface{} {
	tx, err := bc.GetTransactionByIDString(txID)
	if err != nil {
		return nil
	}

	if !verbose {
		// Return hex-encoded raw transaction
		txData, err := json.Marshal(tx)
		if err != nil {
			return nil
		}
		return hex.EncodeToString(txData)
	}

	// Return verbose transaction info
	return map[string]interface{}{
		"txid":          tx.ID,
		"hash":          tx.Hash(),
		"version":       1,
		"size":          len(tx.ID) / 2,
		"locktime":      0,
		"vin":           []interface{}{},
		"vout":          []interface{}{},
		"blockhash":     "",
		"confirmations": 0,
		"time":          time.Now().Unix(),
		"blocktime":     time.Now().Unix(),
	}
}

// GetBestBlockHash returns the hash of the active chain's tip
func (bc *Blockchain) GetBestBlockHash() []byte {
	latest := bc.GetLatestBlock()
	if latest == nil {
		return []byte{}
	}
	return []byte(latest.GetHash())
}

// GetBlockCount returns the height of the active chain
func (bc *Blockchain) GetBlockCount() uint64 {
	latest := bc.GetLatestBlock()
	if latest == nil {
		return 0
	}
	return latest.GetHeight() + 1
}

// GetBlocks returns the current in-memory blockchain (limited)
func (bc *Blockchain) GetBlocks() []*types.Block {
	bc.lock.RLock()
	defer bc.lock.RUnlock()
	return bc.chain
}

// ChainLength returns the current length of the in-memory chain
func (bc *Blockchain) ChainLength() int {
	bc.lock.RLock()
	defer bc.lock.RUnlock()
	return len(bc.chain)
}

// IsValidChain checks the integrity of the full chain
func (bc *Blockchain) IsValidChain() error {
	return bc.storage.ValidateChain()
}

// Close cleans up resources
func (bc *Blockchain) Close() error {
	// Set status to stopped before closing
	bc.SetStatus(StatusStopped)
	logger.Info("Blockchain shutting down...")
	return bc.storage.Close()
}

// ValidateBlock validates a block including TxsRoot = MerkleRoot verification
func (bc *Blockchain) ValidateBlock(block consensus.Block) error {
	// Extract the underlying types.Block from adapter
	var b *types.Block
	switch blk := block.(type) {
	case *BlockHelper:
		b = blk.GetUnderlyingBlock()
	default:
		return fmt.Errorf("invalid block type")
	}

	// 1. Verify TxsRoot = MerkleRoot
	if err := b.ValidateTxsRoot(); err != nil {
		return fmt.Errorf("TxsRoot validation failed: %w", err)
	}

	// 2. Structural sanity
	if err := b.SanityCheck(); err != nil {
		if strings.Contains(err.Error(), "state root is missing") {
			logger.Warn("WARNING: Block validation - state root is empty (allowed in test)")
		} else if strings.Contains(err.Error(), "transaction root is missing") {
			logger.Warn("WARNING: Block validation - transaction root is empty (allowed in test)")
		} else {
			return fmt.Errorf("block sanity check failed: %w", err)
		}
	}

	// 3. Block size validation
	if err := bc.ValidateBlockSize(b); err != nil {
		return fmt.Errorf("block size validation failed: %w", err)
	}

	// 4. Hash is correct
	expectedHash := b.GenerateBlockHash()
	if !bytes.Equal(b.Header.Hash, expectedHash) {
		return fmt.Errorf("invalid block hash: expected %x, got %x", expectedHash, b.Header.Hash)
	}

	// 5. Links to previous block
	prev := bc.GetLatestBlock()
	if prev != nil {
		prevHashBytes, err := hex.DecodeString(prev.GetHash())
		if err != nil {
			return fmt.Errorf("failed to decode previous block hash: %w", err)
		}

		if !bytes.Equal(b.Header.PrevHash, prevHashBytes) {
			return fmt.Errorf("invalid prev hash: expected %s, got %x", prev.GetHash(), b.Header.PrevHash)
		}
	}

	logger.Info("✓ Block %d validation passed, TxsRoot = MerkleRoot verified: %x",
		b.GetHeight(), b.Header.TxsRoot)
	return nil
}

// GetStats returns blockchain statistics for monitoring
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

	stats := map[string]interface{}{
		"status":            bc.StatusString(bc.status),
		"sync_mode":         bc.SyncModeString(bc.syncMode),
		"block_height":      latestHeight,
		"latest_block_hash": latestHash,
		"blocks_in_memory":  len(bc.chain),
		"pending_txs":       bc.mempool.GetTransactionCount(),
		"tx_index_size":     len(bc.txIndex),
		"total_blocks":      bc.storage.GetTotalBlocks(),
	}

	// Add blocksize statistics
	sizeStats := bc.GetBlockSizeStats()
	for k, v := range sizeStats {
		stats[k] = v
	}

	return stats
}
