// MIT License
//
// # Copyright (c) 2024 sphinx-core
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

// go/src/params/commit/header.go
// go/src/params/commit/header.go
package commit

import (
	"fmt"
	"time"
)

// ChainParameters defines the Sphinx blockchain identification parameters
type ChainParameters struct {
	ChainID       uint64 // Unique chain identifier
	ChainName     string // Human-readable chain name
	Symbol        string // Native token symbol
	GenesisTime   int64  // Genesis block timestamp
	GenesisHash   string // Genesis block hash
	Version       string // Protocol version
	MagicNumber   uint32 // Network magic number for peer identification
	DefaultPort   uint16 // Default P2P port
	BIP44CoinType uint32 // BIP44 coin type for wallet derivation
	LedgerName    string // Name recognized by Ledger hardware
}

// SphinxChainParams returns the mainnet parameters for Sphinx blockchain
func SphinxChainParams() *ChainParameters {
	return &ChainParameters{
		ChainID:       7331, // "SPX" in leet speak
		ChainName:     "Sphinx",
		Symbol:        "SPX",
		GenesisTime:   1731375284,            // Your genesis timestamp
		GenesisHash:   "sphinx-genesis-2024", // Your genesis hash
		Version:       "1.0.0",
		MagicNumber:   0x53504858, // "SPHX" in ASCII
		DefaultPort:   32307,      // Your default port
		BIP44CoinType: 7331,       // Same as ChainID for consistency
		LedgerName:    "Sphinx",
	}
}

// TestnetChainParams returns testnet parameters
func TestnetChainParams() *ChainParameters {
	params := SphinxChainParams()
	params.ChainID = 17331 // Testnet chain ID
	params.ChainName = "Sphinx Testnet"
	params.GenesisHash = "sphinx-testnet-genesis"
	params.MagicNumber = 0x74504858 // "tPHX"
	return params
}

// RegtestChainParams returns regression test parameters
func RegtestChainParams() *ChainParameters {
	params := SphinxChainParams()
	params.ChainID = 27331 // Regtest chain ID
	params.ChainName = "Sphinx Regtest"
	params.GenesisHash = "sphinx-regtest-genesis"
	params.MagicNumber = 0x72504858 // "rPHX"
	return params
}

// GenerateHeaders generates ledger and asset headers for SPX with proper chain identification
func GenerateHeaders(ledger, asset string, amount float64, address string) string {
	params := SphinxChainParams()

	return fmt.Sprintf(
		"Chain: %s (ID: %d)\nAsset: %s\nAmount: %.6e\nAddress: %s\nNetwork: %s\nVersion: %s",
		params.ChainName,
		params.ChainID,
		asset,
		amount,
		address,
		params.ChainName,
		params.Version,
	)
}

// GenerateLedgerHeaders generates headers specifically formatted for Ledger hardware
func GenerateLedgerHeaders(operation string, amount float64, address string, memo string) string {
	params := SphinxChainParams()

	return fmt.Sprintf(
		"=== SPHINX LEDGER OPERATION ===\n"+
			"Chain: %s\n"+
			"Chain ID: %d\n"+
			"Operation: %s\n"+
			"Amount: %.6f SPX\n"+
			"Address: %s\n"+
			"Memo: %s\n"+
			"BIP44: 44'/7331'/0'/0/0\n"+
			"Timestamp: %d\n"+
			"========================",
		params.ChainName,
		params.ChainID,
		operation,
		amount,
		address,
		memo,
		time.Now().Unix(),
	)
}

// ValidateChainID validates if a chain ID belongs to Sphinx network
func ValidateChainID(chainID uint64) bool {
	mainnet := SphinxChainParams()
	testnet := TestnetChainParams()
	regtest := RegtestChainParams()

	return chainID == mainnet.ChainID ||
		chainID == testnet.ChainID ||
		chainID == regtest.ChainID
}

// GetNetworkName returns human-readable network name from chain ID
func GetNetworkName(chainID uint64) string {
	switch chainID {
	case SphinxChainParams().ChainID:
		return "Sphinx Mainnet"
	case TestnetChainParams().ChainID:
		return "Sphinx Testnet"
	case RegtestChainParams().ChainID:
		return "Sphinx Regtest"
	default:
		return "Unknown Network"
	}
}

// GenerateGenesisInfo returns formatted genesis block information
func GenerateGenesisInfo() string {
	params := SphinxChainParams()
	genesisTime := time.Unix(params.GenesisTime, 0)

	return fmt.Sprintf(
		"=== SPHINX GENESIS BLOCK ===\n"+
			"Chain: %s\n"+
			"Chain ID: %d\n"+
			"Genesis Time: %s\n"+
			"Genesis Hash: %s\n"+
			"Symbol: %s\n"+
			"BIP44 Coin Type: %d\n"+
			"Protocol Version: %s\n"+
			"=========================",
		params.ChainName,
		params.ChainID,
		genesisTime.Format(time.RFC1123),
		params.GenesisHash,
		params.Symbol,
		params.BIP44CoinType,
		params.Version,
	)
}

// SoftForkParameters defines potential soft fork parameters
type SoftForkParameters struct {
	Name                string
	Bit                 uint8
	StartTime           int64
	Timeout             int64
	MinActivationHeight uint64
}

// GetSoftForks returns active and upcoming soft forks
func GetSoftForks() map[string]*SoftForkParameters {
	return map[string]*SoftForkParameters{
		"spx-segwit": {
			Name:                "SPX Segregated Witness",
			Bit:                 1,
			StartTime:           time.Now().AddDate(0, 1, 0).Unix(), // 1 month from now
			Timeout:             time.Now().AddDate(1, 0, 0).Unix(), // 1 year from now
			MinActivationHeight: 100000,
		},
		"spx-taproot": {
			Name:                "SPX Taproot",
			Bit:                 2,
			StartTime:           time.Now().AddDate(0, 6, 0).Unix(), // 6 months from now
			Timeout:             time.Now().AddDate(2, 0, 0).Unix(), // 2 years from now
			MinActivationHeight: 200000,
		},
	}
}

// IsSoftForkActive checks if a soft fork is active at given height and time
func IsSoftForkActive(forkName string, blockHeight uint64, blockTime int64) bool {
	forks := GetSoftForks()
	fork, exists := forks[forkName]
	if !exists {
		return false
	}

	return blockTime >= fork.StartTime &&
		blockHeight >= fork.MinActivationHeight &&
		blockTime <= fork.Timeout
}

// GenerateForkHeader generates headers for soft fork activation
func GenerateForkHeader(forkName string) string {
	forks := GetSoftForkParameters()
	fork, exists := forks[forkName]
	if !exists {
		return "Unknown fork"
	}

	return fmt.Sprintf(
		"=== SPHINX SOFT FORK ===\n"+
			"Fork: %s\n"+
			"Activation Bit: %d\n"+
			"Start Time: %s\n"+
			"Timeout: %s\n"+
			"Min Height: %d\n"+
			"=======================",
		fork.Name,
		fork.Bit,
		time.Unix(fork.StartTime, 0).Format(time.RFC1123),
		time.Unix(fork.Timeout, 0).Format(time.RFC1123),
		fork.MinActivationHeight,
	)
}

// Helper function to get soft forks (duplicate for internal use)
func GetSoftForkParameters() map[string]*SoftForkParameters {
	return GetSoftForks()
}
