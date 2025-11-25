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
var genesisBlockDefinition = &types.BlockHeader{
	Version:    1,
	Height:     0,
	Timestamp:  1732070400, // Fixed: Nov 20, 2024 00:00:00 UTC
	Difficulty: big.NewInt(1),
	Nonce:      common.FormatNonce(1),    // FIXED: Start with "0000000000000001"
	TxsRoot:    common.SpxHash([]byte{}), // Empty transactions root
	StateRoot:  common.SpxHash([]byte("sphinx-genesis-state-root")),
	GasLimit:   big.NewInt(5000), // Initial gas limit
	GasUsed:    big.NewInt(0),
	ExtraData:  []byte("Sphinx Network Genesis Block - Decentralized Future"),
	Miner:      make([]byte, 20), // Zero address for genesis
	ParentHash: make([]byte, 32), // Genesis has no parent
	UnclesHash: common.SpxHash([]byte("genesis-no-uncles")),
}

// GetGenesisBlockDefinition returns the standardized genesis block definition
func GetGenesisBlockDefinition() *types.BlockHeader {
	// Return a copy to prevent modification
	return &types.BlockHeader{
		Version:    genesisBlockDefinition.Version,
		Height:     genesisBlockDefinition.Height,
		Timestamp:  genesisBlockDefinition.Timestamp,
		Difficulty: new(big.Int).Set(genesisBlockDefinition.Difficulty),
		Nonce:      common.FormatNonce(1), // FIXED: Ensure consistent nonce format "0000000000000001"
		TxsRoot:    append([]byte{}, genesisBlockDefinition.TxsRoot...),
		StateRoot:  append([]byte{}, genesisBlockDefinition.StateRoot...),
		GasLimit:   new(big.Int).Set(genesisBlockDefinition.GasLimit),
		GasUsed:    new(big.Int).Set(genesisBlockDefinition.GasUsed),
		ExtraData:  append([]byte{}, genesisBlockDefinition.ExtraData...),
		Miner:      append([]byte{}, genesisBlockDefinition.Miner...),
		ParentHash: append([]byte{}, genesisBlockDefinition.ParentHash...),
		UnclesHash: append([]byte{}, genesisBlockDefinition.UnclesHash...),
	}
}

// CreateStandardGenesisBlock creates a standardized genesis block that all nodes should use
func CreateStandardGenesisBlock() *types.Block {
	// Create the genesis header directly to ensure all fields are properly set
	genesisHeader := &types.BlockHeader{
		Version:    1,
		Block:      0, // Same as Height
		Height:     0,
		Timestamp:  1732070400,               // Fixed: Nov 20, 2024 00:00:00 UTC
		Difficulty: big.NewInt(17179869184),  // Substantial initial difficulty
		Nonce:      common.FormatNonce(1),    // FIXED: "0000000000000001"
		TxsRoot:    common.SpxHash([]byte{}), // Empty transactions root
		StateRoot:  common.SpxHash([]byte("sphinx-genesis-state-root")),
		GasLimit:   big.NewInt(5000), // Initial gas limit
		GasUsed:    big.NewInt(0),
		ExtraData:  []byte("Sphinx Network Genesis Block - Decentralized Future"),
		Miner:      make([]byte, 20), // Zero address for genesis
		ParentHash: make([]byte, 32), // Genesis has no parent
		UnclesHash: common.SpxHash([]byte("genesis-no-uncles")),
		Hash:       []byte{}, // Will be set by FinalizeHash
	}

	// Create empty uncles slice for genesis
	emptyUncles := []*types.BlockHeader{}

	// Create block body with empty transactions and uncles
	genesisBody := types.NewBlockBody([]*types.Transaction{}, emptyUncles)
	genesis := types.NewBlock(genesisHeader, genesisBody)

	// Finalize the hash
	genesis.FinalizeHash()

	// Log the genesis block details for verification
	logger.Info("✅ Created standardized genesis block:")
	logger.Info("   - Height: %d", genesis.Header.Height)
	logger.Info("   - Nonce: %s", genesis.Header.Nonce)
	logger.Info("   - Hash: %s", genesis.GetHash())
	logger.Info("   - Difficulty: %s", genesis.Header.Difficulty.String())

	return genesis
}

// GetGenesisHash returns the standardized genesis hash that ALL nodes should use
func GetGenesisHash() string {
	genesis := CreateStandardGenesisBlock()
	hash := genesis.GetHash()

	// Ensure it has the GENESIS_ prefix
	if !strings.HasPrefix(hash, "GENESIS_") {
		// Regenerate with proper prefix
		genesis.FinalizeHash()
		hash = genesis.GetHash()
	}

	logger.Info("Standardized genesis hash: %s", hash)
	return hash
}

// GenerateGenesisHash is deprecated - use GetGenesisHash instead for consistency
func GenerateGenesisHash() string {
	logger.Warn("GenerateGenesisHash is deprecated, using GetGenesisHash for consistency")
	return GetGenesisHash()
}
