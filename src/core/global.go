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

// go/src/core/global.go
package core

import (
	"encoding/hex"
	"math/big"
	"strings"

	"github.com/sphinx-core/go/src/common"
	types "github.com/sphinx-core/go/src/core/transaction"
	logger "github.com/sphinx-core/go/src/log"
)

// Constants for blockchain status, sync modes, etc.
const (
	StatusInitializing BlockchainStatus = iota
	StatusSyncing
	StatusRunning
	StatusStopped
	StatusForked
)

const (
	SyncModeFull SyncMode = iota
	SyncModeFast
	SyncModeLight
)

const (
	ImportedBest BlockImportResult = iota
	ImportedSide
	ImportedExisting
	ImportInvalid
	ImportError
)

const (
	CacheTypeBlock CacheType = iota
	CacheTypeTransaction
	CacheTypeReceipt
	CacheTypeState
)

// Global genesis block definition with comprehensive data
// Global genesis block definition with comprehensive data
var genesisBlockDefinition = &types.BlockHeader{
	Version:    1,
	Height:     0,
	Timestamp:  1732070400,               // Fixed: Nov 20, 2024 00:00:00 UTC
	PrevHash:   make([]byte, 32),         // 32 bytes of zeros
	Difficulty: big.NewInt(17179869184),  // Substantial initial difficulty
	Nonce:      66,                       // Meaningful nonce
	TxsRoot:    common.SpxHash([]byte{}), // Empty transactions root
	StateRoot:  common.SpxHash([]byte("sphinx-genesis-state-root")),
	GasLimit:   big.NewInt(5000), // Initial gas limit
	GasUsed:    big.NewInt(0),
	ExtraData:  []byte("Sphinx Network Genesis Block - Decentralized Future"),
	Miner:      make([]byte, 20), // Zero address for genesis

	// FIX: Set meaningful values for ParentHash and UnclesHash
	ParentHash: make([]byte, 32),                    // Genesis has no parent, so use zeros like PrevHash
	UnclesHash: common.SpxHash([]byte("no-uncles")), // Hash indicating no uncles
}

// GenerateGenesisHash creates a deterministic genesis hash that starts with "GENESIS_"
func GenerateGenesisHash() string {
	// Create genesis block with all fields
	genesisHeader := &types.BlockHeader{
		Version:    1,
		Height:     0,
		Timestamp:  1732070400,
		PrevHash:   make([]byte, 32),
		Difficulty: big.NewInt(17179869184),
		Nonce:      66,
		TxsRoot:    common.SpxHash([]byte{}),
		StateRoot:  common.SpxHash([]byte("sphinx-genesis-state-root")),
		GasLimit:   big.NewInt(5000),
		GasUsed:    big.NewInt(0),
		ExtraData:  []byte("Sphinx Network Genesis Block - Decentralized Future"),
		Miner:      make([]byte, 20),
		ParentHash: make([]byte, 32),                            // Genesis has no parent
		UnclesHash: common.SpxHash([]byte("genesis-no-uncles")), // Meaningful uncles hash
	}

	genesisBody := types.NewBlockBody([]*types.Transaction{}, []byte{})
	genesis := types.NewBlock(genesisHeader, genesisBody)

	// Calculate the hash - this will create the GENESIS_ prefixed hash
	genesis.FinalizeHash()
	hash := genesis.GetHash()

	logger.Info("🔷 Raw genesis hash: %s", hash)

	// CRITICAL FIX: For chain parameters, use only the hex part (without GENESIS_ prefix)
	if strings.HasPrefix(hash, "GENESIS_") && len(hash) > 8 {
		hexPart := hash[8:] // Remove "GENESIS_" prefix
		if isHexString(hexPart) {
			logger.Info("🔷 Using hex-only genesis hash for chain params: %s", hexPart)
			return hexPart
		}
	}

	// Fallback: if it's already hex, use as-is
	logger.Info("🔷 Using existing genesis hash: %s", hash)
	return hash
}

// GetGenesisHash returns the consistent genesis hash for all nodes
// GetGenesisHash returns the actual genesis hash with GENESIS_ prefix
func GetGenesisHash() string {
	// Calculate the actual genesis block hash
	genesisHeader := &types.BlockHeader{}
	*genesisHeader = *genesisBlockDefinition

	genesisBody := types.NewBlockBody([]*types.Transaction{}, []byte{})
	genesis := types.NewBlock(genesisHeader, genesisBody)

	// Let the block generate its own hash
	genesis.FinalizeHash()

	// Get the actual hash that was calculated
	actualGenesisHash := genesis.GetHash()

	// CRITICAL: Ensure consistent format - always return with GENESIS_ prefix
	if !strings.HasPrefix(actualGenesisHash, "GENESIS_") {
		// If it doesn't have the prefix, add it
		hashBytes := genesis.GenerateBlockHash()
		hexHash := hex.EncodeToString(hashBytes)
		actualGenesisHash = "GENESIS_" + hexHash
		logger.Info("Added GENESIS_ prefix to genesis hash: %s", actualGenesisHash)
	}

	logger.Info("Using genesis hash with prefix: %s", actualGenesisHash)
	return actualGenesisHash
}
