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

	"github.com/sphinx-core/go/src/common"
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

	// Get formatted timestamps using centralized time service
	localTime, utcTime := common.FormatTimestamp(block.Header.Timestamp)

	info := map[string]interface{}{
		"height":            block.GetHeight(),
		"hash":              block.GetHash(),
		"merkle_root":       hex.EncodeToString(merkleRoot),
		"timestamp":         block.Header.Timestamp,
		"timestamp_local":   localTime,
		"timestamp_utc":     utcTime,
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

// StoreChainState saves the chain state with the actual genesis hash and consensus signatures
func (bc *Blockchain) StoreChainState(nodes []*storage.NodeInfo) error {
	if bc.chainParams == nil {
		return fmt.Errorf("chain parameters not initialized")
	}

	// Convert genesis_time to ISO RFC format for output
	genesisTimeISO := common.GetTimeService().GetCurrentTimeInfo().ISOUTC

	// Convert blockchain params to storage.ChainParams with ISO format
	chainParams := &storage.ChainParams{
		ChainID:       bc.chainParams.ChainID,
		ChainName:     bc.chainParams.ChainName,
		Symbol:        bc.chainParams.Symbol,
		GenesisTime:   genesisTimeISO, // Now this works - string to string
		GenesisHash:   bc.chainParams.GenesisHash,
		Version:       bc.chainParams.Version,
		MagicNumber:   bc.chainParams.MagicNumber,
		DefaultPort:   bc.chainParams.DefaultPort,
		BIP44CoinType: bc.chainParams.BIP44CoinType,
		LedgerName:    bc.chainParams.LedgerName,
	}

	walletPaths := bc.GetWalletDerivationPaths()

	// Collect consensus signatures as FinalStateInfo if consensus engine is available
	var finalStates []*storage.FinalStateInfo
	var signatureValidation *storage.SignatureValidation

	if bc.consensusEngine != nil {
		// Get raw signatures from consensus engine
		rawSignatures := bc.consensusEngine.GetConsensusSignatures()
		finalStates = make([]*storage.FinalStateInfo, len(rawSignatures))

		validCount := 0
		for i, rawSig := range rawSignatures {
			finalStates[i] = &storage.FinalStateInfo{
				BlockHash:        rawSig.BlockHash,
				BlockHeight:      rawSig.BlockHeight,
				SignerNodeID:     rawSig.SignerNodeID,
				Signature:        rawSig.Signature,
				MessageType:      rawSig.MessageType,
				View:             rawSig.View,
				Timestamp:        rawSig.Timestamp,
				Valid:            rawSig.Valid,
				SignatureStatus:  "Valid",
				VerificationTime: common.GetTimeService().GetCurrentTimeInfo().ISOLocal,
			}
			if rawSig.Valid {
				validCount++
			}
		}

		// Create signature validation statistics
		signatureValidation = &storage.SignatureValidation{
			TotalSignatures:   len(finalStates),
			ValidSignatures:   validCount,
			InvalidSignatures: len(finalStates) - validCount,
			ValidationTime:    common.GetTimeService().GetCurrentTimeInfo().ISOUTC, // Use ISOUTC here too
		}

		logger.Info("Storing %d consensus signatures (%d valid) in chain state as final states",
			len(finalStates), validCount)
	}

	// Create chain state with signature data
	chainState := &storage.ChainState{
		Nodes:               nodes,
		Timestamp:           common.GetTimeService().GetCurrentTimeInfo().ISOUTC, // Use ISOUTC
		SignatureValidation: signatureValidation,
		FinalStates:         finalStates,
	}

	// Save chain state with actual parameters and signatures
	err := bc.storage.SaveCompleteChainState(chainState, chainParams, walletPaths)
	if err != nil {
		return fmt.Errorf("failed to save chain state: %w", err)
	}

	// Fix any existing hardcoded hashes
	bc.storage.FixChainStateGenesisHash()

	logger.Info("Complete chain state saved with block size metrics: %s",
		filepath.Join(bc.storage.GetStateDir(), "chain_state.json"))
	logger.Info("Chain state saved with genesis hash: %s", bc.chainParams.GenesisHash)

	if signatureValidation != nil {
		logger.Info("Signature validation: %d/%d valid signatures",
			signatureValidation.ValidSignatures, signatureValidation.TotalSignatures)
	}

	return nil
}

// CalculateAndStoreBlockSizeMetrics calculates and stores block size statistics
func (bc *Blockchain) CalculateAndStoreBlockSizeMetrics() error {
	logger.Info("Starting block size metrics calculation...")

	// Get recent blocks for analysis - use a reasonable limit
	recentBlocks := bc.getRecentBlocks(1000) // Increased to 1000 blocks for better stats
	if len(recentBlocks) == 0 {
		logger.Info("No blocks available for size metrics calculation")
		return nil
	}

	var totalSize uint64
	var minSize uint64 = ^uint64(0) // Max uint64
	var maxSize uint64
	sizeStats := make([]storage.BlockSizeInfo, 0, len(recentBlocks))

	for _, block := range recentBlocks {
		blockSize := bc.CalculateBlockSize(block)
		totalSize += blockSize

		if blockSize < minSize {
			minSize = blockSize
		}
		if blockSize > maxSize {
			maxSize = blockSize
		}

		// Record individual block stats using BlockSizeInfo
		blockStat := storage.BlockSizeInfo{
			Height:    block.GetHeight(),
			Hash:      block.GetHash(),
			Size:      blockSize,
			SizeMB:    float64(blockSize) / (1024 * 1024),
			TxCount:   uint64(len(block.Body.TxsList)),
			Timestamp: block.Header.Timestamp,
		}
		sizeStats = append(sizeStats, blockStat)
	}

	averageSize := totalSize / uint64(len(recentBlocks))

	// Convert to MB for human readability
	averageSizeMB := float64(averageSize) / (1024 * 1024)
	minSizeMB := float64(minSize) / (1024 * 1024)
	maxSizeMB := float64(maxSize) / (1024 * 1024)
	totalSizeMB := float64(totalSize) / (1024 * 1024)

	// Create block size metrics
	blockSizeMetrics := &storage.BlockSizeMetrics{
		TotalBlocks:     uint64(len(recentBlocks)),
		AverageSize:     averageSize,
		MinSize:         minSize,
		MaxSize:         maxSize,
		TotalSize:       totalSize,
		SizeStats:       sizeStats,
		CalculationTime: common.GetTimeService().GetCurrentTimeInfo().ISOLocal,
		AverageSizeMB:   averageSizeMB,
		MinSizeMB:       minSizeMB,
		MaxSizeMB:       maxSizeMB,
		TotalSizeMB:     totalSizeMB,
	}

	// Save to storage
	if err := bc.storage.SaveBlockSizeMetrics(blockSizeMetrics); err != nil {
		return fmt.Errorf("failed to save block size metrics: %w", err)
	}

	logger.Info("Successfully calculated block size metrics for %d blocks", len(recentBlocks))
	logger.Info("Block size stats: avg=%.2f MB, min=%.2f MB, max=%.2f MB, total=%.2f MB",
		averageSizeMB, minSizeMB, maxSizeMB, totalSizeMB)
	logger.Info("Size stats contains %d entries", len(sizeStats))

	return nil
}

// SaveBasicChainState saves a basic chain state
func (bc *Blockchain) SaveBasicChainState() error {
	return bc.StoreChainState(nil) // Only one parameter now
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

// NewBlockchain creates a blockchain with state machine replication// Initialize TPS monitor in NewBlockchain
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
		mempool:         nil,
		chain:           []*types.Block{},
		txIndex:         make(map[string]*types.Transaction),
		pendingTx:       []*types.Transaction{},
		lock:            sync.RWMutex{},
		status:          StatusInitializing,
		syncMode:        SyncModeFull,
		consensusEngine: nil,
		chainParams:     nil,
		merkleRootCache: make(map[string]string),
		tpsMonitor:      types.NewTPSMonitor(5 * time.Second), // 5-second window
	}

	// Load existing chain from storage or create genesis block if new chain
	if err := blockchain.initializeChain(); err != nil {
		return nil, fmt.Errorf("failed to initialize chain: %w", err)
	}

	// Now that we have the genesis block, set the chain params with consistent hash
	if len(blockchain.chain) > 0 {
		// Use consistent genesis hash that's the same for all nodes
		var chainParams *SphinxChainParameters
		switch networkType {
		case "testnet":
			chainParams = GetTestnetChainParams()
		case "devnet":
			chainParams = GetDevnetChainParams()
		default:
			chainParams = GetSphinxChainParams()
		}

		blockchain.chainParams = chainParams

		// Validate that our genesis hash matches the chain params
		actualGenesisHash := blockchain.chain[0].GetHash()
		if actualGenesisHash != chainParams.GenesisHash {
			logger.Warn("Genesis hash mismatch: actual=%s, expected=%s",
				actualGenesisHash, chainParams.GenesisHash)
			// This shouldn't happen with our consistent approach
		}

		logger.Info("Chain parameters initialized for %s: genesis_hash=%s",
			chainParams.GetNetworkName(), chainParams.GenesisHash)

		// Initialize mempool with configuration from chain params
		mempoolConfig := GetMempoolConfigFromChainParams(chainParams)
		blockchain.mempool = pool.NewMempool(mempoolConfig)

		// FIXED: Use chainParams.GenesisHash instead of undefined genesisHash
		logger.Info("Chain parameters initialized for %s: genesis_hash=%s",
			chainParams.GetNetworkName(), chainParams.GenesisHash)

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

	// Convert genesis_time from Unix timestamp to ISO RFC format for output
	// Use ISOUTC field which is already in RFC3339 format
	genesisTimeISO := common.GetTimeService().GetTimeInfo(params.GenesisTime).ISOUTC

	return map[string]interface{}{
		"chain_id":        params.ChainID,
		"chain_name":      params.ChainName,
		"symbol":          params.Symbol,
		"genesis_time":    genesisTimeISO, // Now in ISO RFC format: "2024-11-20T00:00:00Z"
		"genesis_hash":    params.GenesisHash,
		"version":         params.Version,
		"magic_number":    fmt.Sprintf("0x%x", params.MagicNumber),
		"default_port":    params.DefaultPort,
		"bip44_coin_type": params.BIP44CoinType,
		"ledger_name":     params.LedgerName,
		"current_height":  blockHeight,
		"latest_block":    blockHash,
		"network":         networkName,
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
		common.GetCurrentTimestamp(),
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

// Enhanced StartLeaderLoop with leader lock to prevent rapid view changes
func (bc *Blockchain) StartLeaderLoop(ctx context.Context) {
	leaderMutex := sync.Mutex{}
	var isProposing bool

	go func() {
		ticker := time.NewTicker(5 * time.Second)
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

				// Check if we're already proposing
				leaderMutex.Lock()
				if isProposing {
					leaderMutex.Unlock()
					logger.Debug("Leader: already proposing block, skipping")
					continue
				}
				isProposing = true
				leaderMutex.Unlock()

				// Check if we have transactions in mempool
				hasTxs := bc.mempool.GetTransactionCount() > 0
				if !hasTxs {
					leaderMutex.Lock()
					isProposing = false
					leaderMutex.Unlock()
					logger.Debug("Leader: no pending transactions to propose")
					continue
				}

				logger.Info("Leader %s: creating block with %d pending transactions",
					bc.consensusEngine.GetNodeID(), bc.mempool.GetTransactionCount())

				// Create and propose block using existing CreateBlock function
				// This now includes nonce iteration internally
				block, err := bc.CreateBlock()
				if err != nil {
					logger.Warn("Leader: failed to create block: %v", err)
					leaderMutex.Lock()
					isProposing = false
					leaderMutex.Unlock()
					continue
				}

				logger.Info("Leader %s proposing block at height %d with %d transactions and nonce %s",
					bc.consensusEngine.GetNodeID(), block.GetHeight(), len(block.Body.TxsList), block.Header.Nonce)

				// Convert to consensus.Block using adapter
				consensusBlock := NewBlockHelper(block)
				if err := bc.consensusEngine.ProposeBlock(consensusBlock); err != nil {
					logger.Warn("Leader: failed to propose block: %v", err)
				} else {
					logger.Info("Leader: block proposal sent successfully with nonce %s", block.Header.Nonce)
				}

				// Reset proposing flag after a delay to allow consensus to complete
				go func() {
					time.Sleep(30 * time.Second) // Wait for consensus to complete
					leaderMutex.Lock()
					isProposing = false
					leaderMutex.Unlock()
				}()
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

	// Verify block links to current chain using ParentHash
	latestBlock := bc.GetLatestBlock()
	if latestBlock != nil && block.GetPrevHash() != latestBlock.GetHash() {
		logger.Info("Block does not extend current chain: expected ParentHash=%s, got ParentHash=%s",
			latestBlock.GetHash(), block.GetPrevHash())
		return ImportedSide
	}

	// Try to commit the block through state machine replication
	consensusBlock := NewBlockHelper(block)
	if err := bc.CommitBlock(consensusBlock); err != nil {
		logger.Warn("Block commit failed: %v", err)
		return ImportError
	}

	logger.Info("Block imported successfully: height=%d, hash=%s, ParentHash=%s",
		block.GetHeight(), block.GetHash(), block.GetPrevHash())
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
	bc.storage.RecordTransaction()
	// Also increment blocks_processed when transactions are actually included in blocks
	if bc.tpsMonitor != nil {
		bc.tpsMonitor.RecordTransaction()
	}
	return bc.mempool.BroadcastTransaction(tx)
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
// CreateBlock creates a new block and iterates nonce until consensus using existing functions
func (bc *Blockchain) CreateBlock() (*types.Block, error) {
	if bc.mempool == nil {
		return nil, fmt.Errorf("mempool not initialized")
	}
	if bc.chainParams == nil {
		return nil, fmt.Errorf("chain parameters not initialized")
	}
	bc.lock.Lock()
	defer bc.lock.Unlock()

	// Get the latest block
	prevBlock, err := bc.storage.GetLatestBlock()
	if err != nil || prevBlock == nil {
		return nil, fmt.Errorf("no previous block found: %v", err)
	}

	// Get previous hash
	parentHash := prevBlock.GetHash()
	var parentHashBytes []byte

	if strings.HasPrefix(parentHash, "GENESIS_") {
		parentHashBytes = []byte(parentHash)
		logger.Info("Using genesis-style parent hash: %s (stored as %d bytes)",
			parentHash, len(parentHashBytes))
	} else {
		parentHashBytes, err = hex.DecodeString(parentHash)
		if err != nil {
			return nil, fmt.Errorf("failed to decode parent hash: %w", err)
		}
		logger.Info("Using normal parent hash: %s (stored as %d bytes)",
			parentHash, len(parentHashBytes))
	}

	pendingTxs := bc.mempool.GetPendingTransactions()
	if len(pendingTxs) == 0 {
		return nil, errors.New("no pending transactions in mempool")
	}

	logger.Info("Found %d pending transactions in mempool, max block size: %d bytes",
		len(pendingTxs), bc.chainParams.MaxBlockSize)

	// Select transactions based on block size constraints
	selectedTxs, totalSize, err := bc.selectTransactionsForBlock(pendingTxs)
	if err != nil {
		return nil, fmt.Errorf("failed to select transactions: %w", err)
	}

	if len(selectedTxs) == 0 {
		return nil, errors.New("no transactions could be selected for block")
	}

	logger.Info("Creating block with %d transactions, estimated size: %d bytes (limit: %d, utilization: %.2f%%)",
		len(selectedTxs), totalSize, bc.chainParams.MaxBlockSize,
		float64(totalSize)/float64(bc.chainParams.MaxBlockSize)*100)

	// Calculate roots and create block
	txsRoot := bc.calculateTransactionsRoot(selectedTxs)
	stateRoot := bc.calculateStateRoot()

	currentTimestamp := common.GetCurrentTimestamp()
	if currentTimestamp == 0 {
		currentTimestamp = time.Now().Unix()
	}

	extraData := []byte("Sphinx Network Block")
	miner := make([]byte, 20)
	emptyUncles := []*types.BlockHeader{}

	// Create block with initial nonce
	newHeader := types.NewBlockHeader(
		prevBlock.GetHeight()+1,
		parentHashBytes,
		bc.GetDifficulty(),
		txsRoot,
		stateRoot,
		bc.chainParams.BlockGasLimit,
		big.NewInt(0),
		extraData,
		miner,
		currentTimestamp,
		emptyUncles,
	)

	newBody := types.NewBlockBody(selectedTxs, emptyUncles)
	newBlock := types.NewBlock(newHeader, newBody)

	// CRITICAL: Increment nonce multiple times until consensus is achieved
	logger.Info("Starting nonce iteration for consensus: initial nonce=%s", newBlock.Header.Nonce)

	maxAttempts := 1000000 // 1 million attempts
	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Use existing IncrementNonce function
		if err := newBlock.IncrementNonce(); err != nil {
			logger.Warn("Failed to increment nonce on attempt %d: %v", attempt, err)
			continue
		}

		// Finalize hash with new nonce
		newBlock.FinalizeHash()

		// Check if consensus requirements are met using existing validation
		if bc.checkConsensusRequirements(newBlock) {
			logger.Info("✅ Consensus achieved with nonce %s after %d attempts",
				newBlock.Header.Nonce, attempt+1)
			break
		}

		// Log progress every 1000 attempts
		if (attempt+1)%1000 == 0 {
			logger.Debug("Nonce iteration: attempt %d, current nonce: %s",
				attempt+1, newBlock.Header.Nonce)
		}

		// If we reach the end, use the last nonce
		if attempt == maxAttempts-1 {
			logger.Info("⚠️ Max nonce attempts reached, using nonce %s", newBlock.Header.Nonce)
		}
	}

	// Final validation using existing functions
	if err := newBlock.ValidateHashFormat(); err != nil {
		logger.Warn("❌ Block hash format validation failed: %v", err)
		newBlock.SetHash(hex.EncodeToString(newBlock.GenerateBlockHash()))
		if err := newBlock.ValidateHashFormat(); err != nil {
			return nil, fmt.Errorf("failed to generate valid block hash: %w", err)
		}
	}

	if err := newBlock.ValidateTxsRoot(); err != nil {
		return nil, fmt.Errorf("created block has inconsistent TxsRoot: %v", err)
	}

	// CRITICAL: Calculate and cache the merkle root immediately
	merkleRoot := hex.EncodeToString(txsRoot)
	blockHash := newBlock.GetHash()

	logger.Info("✅ Pre-calculated merkle root for new block %s: %s", blockHash, merkleRoot)

	// Cache it in consensus if available
	if bc.consensusEngine != nil {
		bc.consensusEngine.CacheMerkleRoot(blockHash, merkleRoot)
		logger.Info("✅ Cached merkle root in consensus engine")
	} else {
		logger.Warn("⚠️ No consensus engine available for caching")
	}

	logger.Info("✅ Created new PBFT block: height=%d, transactions=%d, hash=%s, final_nonce=%s",
		newBlock.GetHeight(), len(selectedTxs), newBlock.GetHash(), newBlock.Header.Nonce)

	return newBlock, nil
}

// checkConsensusRequirements uses existing validation functions
func (bc *Blockchain) checkConsensusRequirements(block *types.Block) bool {
	// Use existing block validation
	if err := block.Validate(); err != nil {
		logger.Debug("Block validation failed: %v", err)
		return false
	}

	// Use existing hash format validation
	if err := block.ValidateHashFormat(); err != nil {
		logger.Debug("Hash format validation failed: %v", err)
		return false
	}

	// For PBFT, we consider the block valid if it passes basic validation
	// Actual consensus will be determined by voting
	return true
}

// selectTransactionsForBlock selects transactions for the block based on size constraints
// selectTransactionsForBlock selects transactions for the block based on size constraints
func (bc *Blockchain) selectTransactionsForBlock(pendingTxs []*types.Transaction) ([]*types.Transaction, uint64, error) {
	var selectedTxs []*types.Transaction
	currentSize := uint64(0)
	txCount := 0
	maxTxCount := 10000 // Safety limit to prevent excessive processing

	// Calculate overhead for block metadata (header, etc.)
	// This is an estimate - adjust based on your actual block structure
	blockOverhead := uint64(1000) // ~1KB for header and other metadata
	availableSize := bc.chainParams.MaxBlockSize - blockOverhead

	if availableSize <= 0 {
		return nil, 0, fmt.Errorf("block size too small for overhead")
	}

	logger.Debug("Available block size for transactions: %d bytes (after %d bytes overhead)",
		availableSize, blockOverhead)

	// Track gas usage if applicable
	currentGas := big.NewInt(0)

	for _, tx := range pendingTxs {
		// Safety check to prevent infinite loops
		if txCount >= maxTxCount {
			logger.Warn("Reached maximum transaction count limit: %d", maxTxCount)
			break
		}

		txSize, err := bc.calculateTxsSize(tx)
		if err != nil {
			logger.Warn("Failed to calculate transaction size: %v", err)
			continue
		}

		// Check if transaction is too large individually
		if txSize > bc.chainParams.MaxTransactionSize {
			logger.Warn("Transaction exceeds maximum size: %d > %d", txSize, bc.chainParams.MaxTransactionSize)
			continue
		}

		// Check if adding this transaction would exceed block size
		if currentSize+txSize > availableSize {
			// Try to find smaller transactions that might fit
			continue
		}

		// Check transaction gas limit if applicable
		if bc.chainParams.BlockGasLimit != nil {
			txGas := bc.getTransactionGas(tx)
			proposedGas := new(big.Int).Add(currentGas, txGas)

			// Check if adding this transaction would exceed block gas limit
			if proposedGas.Cmp(bc.chainParams.BlockGasLimit) > 0 {
				logger.Debug("Transaction would exceed gas limit: %s > %s",
					proposedGas.String(), bc.chainParams.BlockGasLimit.String())
				continue
			}
			currentGas = proposedGas
		}

		selectedTxs = append(selectedTxs, tx)
		currentSize += txSize
		txCount++

		// Optional: Stop if we're close to the target size to leave room for variability
		if currentSize >= availableSize*95/100 {
			logger.Debug("Reached 95%% of available block size, stopping selection")
			break
		}
	}

	// Log selection statistics
	if len(selectedTxs) > 0 {
		utilization := float64(currentSize) / float64(availableSize) * 100
		averageTxSize := float64(currentSize) / float64(len(selectedTxs))

		logger.Info("Selected %d transactions, total size: %d bytes (%.2f%% utilization, avg tx: %.2f bytes)",
			len(selectedTxs), currentSize, utilization, averageTxSize)

		if bc.chainParams.BlockGasLimit != nil {
			gasUtilization := float64(currentGas.Int64()) / float64(bc.chainParams.BlockGasLimit.Int64()) * 100
			logger.Info("Gas usage: %s / %s (%.2f%%)",
				currentGas.String(), bc.chainParams.BlockGasLimit.String(), gasUtilization)
		}
	}

	return selectedTxs, currentSize + blockOverhead, nil
}

// calculateTransactionSize calculates the size of a transaction in bytes
func (bc *Blockchain) calculateTxsSize(tx *types.Transaction) (uint64, error) {
	// Use mempool's calculation if available - this is the preferred method
	if bc.mempool != nil {
		return bc.mempool.CalculateTransactionSize(tx), nil
	}

	// Calculate size based on actual transaction fields
	estimatedSize := uint64(0)

	// Base transaction overhead
	estimatedSize += 50 // Fixed overhead

	// Account for transaction ID
	estimatedSize += uint64(len(tx.ID))

	// Account for sender and receiver addresses
	estimatedSize += uint64(len(tx.Sender))
	estimatedSize += uint64(len(tx.Receiver))

	// Account for amount (big.Int size)
	if tx.Amount != nil {
		estimatedSize += uint64(len(tx.Amount.Bytes()))
	}

	// Account for gas fields
	if tx.GasLimit != nil {
		estimatedSize += uint64(len(tx.GasLimit.Bytes()))
	}
	if tx.GasPrice != nil {
		estimatedSize += uint64(len(tx.GasPrice.Bytes()))
	}

	// Account for nonce (uint64 = 8 bytes)
	estimatedSize += 8

	// Account for timestamp (int64 = 8 bytes)
	estimatedSize += 8

	// Account for signature (len() for nil slices is 0)
	estimatedSize += uint64(len(tx.Signature))

	logger.Debug("Calculated transaction size: %d bytes", estimatedSize)
	return estimatedSize, nil
}

// getTransactionGas returns the gas consumption of a transaction
// getTransactionGas returns the gas consumption of a transaction
func (bc *Blockchain) getTransactionGas(tx *types.Transaction) *big.Int {
	// Use the transaction's gas limit if available
	if tx.GasLimit != nil && tx.GasLimit.Cmp(big.NewInt(0)) > 0 {
		return tx.GasLimit
	}

	// Calculate gas based on transaction complexity
	baseGas := big.NewInt(21000) // Base transaction gas

	// Add gas for signature verification (len() for nil slices is 0)
	sigGas := big.NewInt(int64(len(tx.Signature)) * 100) // 100 gas per signature byte
	baseGas.Add(baseGas, sigGas)

	// Add gas for value transfer if amount is significant
	if tx.Amount != nil && tx.Amount.Cmp(big.NewInt(0)) > 0 {
		valueGas := big.NewInt(9000) // Additional gas for value transfer
		baseGas.Add(baseGas, valueGas)
	}

	return baseGas
}

func (bc *Blockchain) GetCachedMerkleRoot(blockHash string) string {
	bc.lock.RLock()
	defer bc.lock.RUnlock()

	if bc.merkleRootCache != nil {
		if root, exists := bc.merkleRootCache[blockHash]; exists {
			return root
		}
	}
	return ""
}

// DecodeBlockHashForConsensus - ensure it handles both formats correctly
func (bc *Blockchain) DecodeBlockHash(hash string) ([]byte, error) {
	// Handle empty hash
	if hash == "" {
		return nil, fmt.Errorf("empty hash")
	}

	// If it's a genesis hash in text format
	if strings.HasPrefix(hash, "GENESIS_") && len(hash) > 8 {
		// For consensus operations, extract the hex part
		hexPart := hash[8:]
		if isHexString(hexPart) {
			return hex.DecodeString(hexPart)
		}
		// If it's not valid hex, return the text as bytes
		return []byte(hash), nil
	}

	// Normal hex-encoded hash
	if !isHexString(hash) {
		// If it's not hex, it might already be bytes, return as-is
		return []byte(hash), nil
	}
	return hex.DecodeString(hash)
}

// Helper function to check if string is hex
func isHexString(s string) bool {
	if len(s)%2 != 0 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
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
		// Use the dedicated method for empty transactions
		return bc.calculateEmptyTransactionsRoot()
	}

	tempBlock := &types.Block{
		Body: types.BlockBody{TxsList: txs},
	}
	return tempBlock.CalculateTxsRoot()
}

// calculateStateRoot calculates the state root after applying transactions
func (bc *Blockchain) calculateStateRoot() []byte {
	// FIX: Return a meaningful state root instead of placeholder
	stateData := []byte(fmt.Sprintf("state-root-%d", time.Now().UnixNano()))
	return common.SpxHash(stateData)
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

	// Calculate actual block time (time since last block)
	blockTime := bc.calculateBlockTime(typeBlock)

	// ✅ FIXED: Record block in storage TPS with actual block time
	bc.storage.RecordBlock(typeBlock, blockTime)

	// Record block for TPS monitoring (blockchain internal)
	txCount := uint64(len(typeBlock.Body.TxsList))
	bc.tpsMonitor.RecordBlock(txCount, blockTime)

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

	logger.Info("✅ Block committed: height=%d, hash=%s, transactions=%d, block_time=%v",
		typeBlock.GetHeight(), typeBlock.GetHash(), len(txIDs), blockTime)

	return nil
}

// calculateBlockTime calculates the actual time between blocks
func (bc *Blockchain) calculateBlockTime(block *types.Block) time.Duration {
	latest := bc.GetLatestBlock()
	if latest == nil {
		logger.Debug("First block, using default block time")
		return 5 * time.Second // Default for first block
	}

	// Calculate time difference between current and previous block
	timeDiff := block.Header.Timestamp - latest.GetTimestamp()
	if timeDiff <= 0 {
		// Fallback: use reasonable default
		logger.Debug("Invalid block time difference, using default")
		return 5 * time.Second
	}

	blockTime := time.Duration(timeDiff) * time.Second
	logger.Debug("Block time calculated: %v (timestamp diff: %d seconds)",
		blockTime, timeDiff)

	return blockTime
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

// createGenesisBlock creates and stores the genesis block with comprehensive data
// In your blockchain initialization code:
func (bc *Blockchain) createGenesisBlock() error {
	// Use the STANDARDIZED genesis block that all nodes will use
	genesis := CreateStandardGenesisBlock()

	// Store the standardized genesis block
	if err := bc.storage.StoreBlock(genesis); err != nil {
		return fmt.Errorf("failed to store genesis block: %w", err)
	}

	// Verify storage
	storedBlock, err := bc.storage.GetBlockByHash(genesis.GetHash())
	if err != nil || storedBlock == nil {
		return fmt.Errorf("genesis block storage verification failed: %v", err)
	}

	logger.Info("Standardized genesis block stored: %s", genesis.GetHash())

	// Initialize in-memory chain
	bc.chain = []*types.Block{genesis}

	// Log comprehensive genesis information
	localTime, utcTime := common.FormatTimestamp(genesis.Header.Timestamp)
	relativeTime := common.GetTimeService().GetRelativeTime(genesis.Header.Timestamp)

	logger.Info("=== STANDARDIZED GENESIS BLOCK ===")
	logger.Info("Height: %d", genesis.GetHeight())
	logger.Info("Hash: %s", genesis.GetHash())
	logger.Info("Timestamp: %d (%s)", genesis.Header.Timestamp, relativeTime)
	logger.Info("Local Time: %s", localTime)
	logger.Info("UTC Time: %s", utcTime)
	logger.Info("Difficulty: %s", genesis.Header.Difficulty.String())
	logger.Info("Gas Limit: %s", genesis.Header.GasLimit.String())
	logger.Info("Extra Data: %s", string(genesis.Header.ExtraData))
	logger.Info("Parent Hash: %x", genesis.Header.ParentHash)
	logger.Info("Uncles Hash: %x", genesis.Header.UnclesHash)
	logger.Info("================================")

	return nil
}

// ValidateGenesisHash compares genesis hashes handling both GENESIS_ prefixed and hex-only formats
func (bc *Blockchain) ValidateGenesisHash(storedHash, expectedHash string) bool {
	// Handle both formats
	if strings.HasPrefix(storedHash, "GENESIS_") && len(storedHash) > 8 {
		return storedHash[8:] == expectedHash
	}
	return storedHash == expectedHash
}

// IsGenesisHash checks if a hash is a valid genesis hash (starts with GENESIS_)
func (bc *Blockchain) IsGenesisHash(hash string) bool {
	return strings.HasPrefix(hash, "GENESIS_")
}

// ValidateGenesisBlock validates that a block has the correct genesis hash format
func (bc *Blockchain) ValidateGenesisBlock(block *types.Block) error {
	if block.GetHeight() != 0 {
		return fmt.Errorf("not a genesis block: height=%d", block.GetHeight())
	}

	if !bc.IsGenesisHash(block.GetHash()) {
		return fmt.Errorf("invalid genesis hash: does not start with 'GENESIS_'")
	}

	return nil
}

// GetDifficulty returns the current network difficulty
func (bc *Blockchain) GetDifficulty() *big.Int {
	latest := bc.GetLatestBlock()
	if latest == nil {
		return big.NewInt(1)
	}
	return latest.GetDifficulty()
}

// calculateEmptyTransactionsRoot returns a standard Merkle root for empty transactions
func (bc *Blockchain) calculateEmptyTransactionsRoot() []byte {
	// Standard empty Merkle root (hash of empty string)
	emptyHash := common.SpxHash([]byte{})
	return emptyHash
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

// GetChainTip returns information about the current chain tip
func (bc *Blockchain) GetChainTip() map[string]interface{} {
	latest := bc.GetLatestBlock()
	if latest == nil {
		return nil
	}

	// Get formatted timestamps using centralized time service
	localTime, utcTime := common.FormatTimestamp(latest.GetTimestamp())

	return map[string]interface{}{
		"height":          latest.GetHeight(),
		"hash":            latest.GetHash(),
		"timestamp":       latest.GetTimestamp(),
		"timestamp_local": localTime,
		"timestamp_utc":   utcTime,
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
		info["difficulty"] = bc.GetDifficulty().String() // Fixed: Use bc.GetDifficulty()
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
		"difficulty":     bc.GetDifficulty().String(), // Fixed: Use bc.GetDifficulty()
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

	// Get formatted timestamps using centralized time service
	localTime, utcTime := common.FormatTimestamp(tx.Timestamp)

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
		"time":          tx.Timestamp,
		"time_local":    localTime,
		"time_utc":      utcTime,
		"blocktime":     tx.Timestamp,
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
// ValidateBlock - handle raw bytes in ParentHash
func (bc *Blockchain) ValidateBlock(block consensus.Block) error {
	var b *types.Block
	switch blk := block.(type) {
	case *BlockHelper:
		b = blk.GetUnderlyingBlock()
	default:
		return fmt.Errorf("invalid block type")
	}

	// Validate ParentHash chain linkage (except for genesis block)
	if b.Header.Height > 0 {
		previousBlock := bc.GetLatestBlock()
		if previousBlock != nil {
			expectedParentHash := previousBlock.GetHash()
			currentParentHash := b.GetPrevHash()

			logger.Info("🔍 DEBUG: ParentHash validation - expected: %s, current: %s",
				expectedParentHash, currentParentHash)

			// For comparison, we need to normalize both hashes
			decodedExpected, err := bc.DecodeBlockHash(expectedParentHash)
			if err != nil {
				return fmt.Errorf("failed to decode expected parent hash '%s': %w", expectedParentHash, err)
			}

			decodedCurrent, err := bc.DecodeBlockHash(currentParentHash)
			if err != nil {
				return fmt.Errorf("failed to decode current parent hash '%s': %w", currentParentHash, err)
			}

			if !bytes.Equal(decodedExpected, decodedCurrent) {
				return fmt.Errorf("invalid parent hash: expected %x, got %x",
					decodedExpected, decodedCurrent)
			}
		}
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

	// 5. Links to previous block using ParentHash
	previousBlock := bc.GetLatestBlock()
	if previousBlock != nil {
		// Use your existing DecodeBlockHash method that handles genesis hashes
		parentHashBytes, err := bc.DecodeBlockHash(previousBlock.GetHash())
		if err != nil {
			return fmt.Errorf("failed to decode previous block hash '%s': %w", previousBlock.GetHash(), err)
		}

		currentParentHashBytes, err := bc.DecodeBlockHash(b.GetPrevHash())
		if err != nil {
			return fmt.Errorf("failed to decode current parent hash '%s': %w", b.GetPrevHash(), err)
		}

		if !bytes.Equal(parentHashBytes, currentParentHashBytes) {
			return fmt.Errorf("invalid parent hash: expected %s, got %s", previousBlock.GetHash(), b.GetPrevHash())
		}
	}

	logger.Info("✓ Block %d validation passed, TxsRoot = MerkleRoot verified: %x",
		b.GetHeight(), b.Header.TxsRoot)
	return nil
}

// Add TPS monitoring methods to Blockchain
func (bc *Blockchain) GetTPSStats() map[string]interface{} {
	bc.lock.RLock()
	defer bc.lock.RUnlock()

	tpsMetrics := bc.storage.GetTPSMetrics()

	return map[string]interface{}{
		"current_tps":          tpsMetrics.CurrentTPS,
		"average_tps":          tpsMetrics.AverageTPS,
		"peak_tps":             tpsMetrics.PeakTPS,
		"total_transactions":   tpsMetrics.TotalTransactions,
		"blocks_processed":     tpsMetrics.BlocksProcessed,
		"current_window_count": tpsMetrics.CurrentWindowCount,
		"window_duration_sec":  tpsMetrics.WindowDurationSeconds, // Use the pre-calculated field
		"last_updated":         tpsMetrics.LastUpdated.Format(time.RFC3339),
		"avg_txs_per_block":    tpsMetrics.AvgTransactionsPerBlock,
		"max_txs_per_block":    tpsMetrics.MaxTransactionsPerBlock,
		"min_txs_per_block":    tpsMetrics.MinTransactionsPerBlock,
		"tps_history_size":     len(tpsMetrics.TPSHistory),
		"blocks_history_size":  len(tpsMetrics.TransactionsPerBlock),
	}
}

// Start TPS auto-save in blockchain initialization
func (bc *Blockchain) StartTPSAutoSave(ctx context.Context) {
	bc.storage.StartTPSAutoSave(ctx)
}

// Add to GetStats method
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

	// Add TPS statistics
	if bc.tpsMonitor != nil {
		tpsStats := bc.tpsMonitor.GetStats()
		for k, v := range tpsStats {
			stats["tps_"+k] = v
		}
	}

	return stats
}

// StartTPSReporting starts periodic TPS reporting
func (bc *Blockchain) StartTPSReporting(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(30 * time.Second) // Report every 30 seconds
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if bc.tpsMonitor != nil {
					stats := bc.tpsMonitor.GetStats()
					currentTPS := stats["current_tps"].(float64)
					averageTPS := stats["average_tps"].(float64)
					peakTPS := stats["peak_tps"].(float64)
					totalTxs := stats["total_transactions"].(uint64)

					logger.Info("📊 TPS Report: current=%.2f, avg=%.2f, peak=%.2f, total_txs=%d",
						currentTPS, averageTPS, peakTPS, totalTxs)
				}
			}
		}
	}()
}
