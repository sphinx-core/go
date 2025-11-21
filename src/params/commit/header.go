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
package commit

import (
	"fmt"
	"time"

	"github.com/sphinx-core/go/src/accounts/key"
)

// SphinxChainParams returns the mainnet parameters for Sphinx blockchain
func SphinxChainParams() *ChainParameters {
	return &ChainParameters{
		ChainID:       7331,             // "SPX" in leet speak
		ChainName:     "Sphinx Mainnet", // Changed from "Sphinx" to "Sphinx Mainnet"
		Symbol:        "SPX",
		GenesisTime:   1731375284,
		GenesisHash:   "sphinx-genesis-2024",
		Version:       "1.0.0",
		MagicNumber:   0x53504858, // "SPHX" in ASCII
		DefaultPort:   32307,
		BIP44CoinType: 7331,             // Should be 7331 for mainnet, not 1
		LedgerName:    "Sphinx Mainnet", // Should match chain_name
	}
}

// TestnetChainParams returns testnet parameters
func TestnetChainParams() *ChainParameters {
	params := SphinxChainParams()
	params.ChainID = 17331 // Testnet chain ID
	params.ChainName = "Sphinx Testnet"
	params.GenesisHash = "sphinx-testnet-genesis"
	params.MagicNumber = 0x74504858 // "tPHX"
	params.BIP44CoinType = 1        // Testnet uses different BIP44 coin type
	params.LedgerName = "Sphinx Testnet"
	return params
}

// RegtestChainParams returns regression test parameters
func RegtestChainParams() *ChainParameters {
	params := SphinxChainParams()
	params.ChainID = 27331 // Regtest chain ID
	params.ChainName = "Sphinx Regtest"
	params.GenesisHash = "sphinx-regtest-genesis"
	params.MagicNumber = 0x72504858 // "rPHX"
	params.BIP44CoinType = 1        // Regtest uses testnet BIP44 coin type
	params.LedgerName = "Sphinx Regtest"
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
// Now delegates to the centralized keystore package
func GenerateLedgerHeaders(operation string, amount float64, address string, memo string) string {
	params := SphinxChainParams()

	// Create appropriate keystore config based on chain parameters
	keystoreConfig := key.NewKeystoreConfig(
		params.ChainID,
		params.ChainName,
		params.BIP44CoinType,
		params.LedgerName,
		params.Symbol,
	)

	return keystoreConfig.GenerateLedgerHeaders(operation, amount, address, memo)
}

// GenerateTestnetLedgerHeaders generates headers for testnet Ledger operations
func GenerateTestnetLedgerHeaders(operation string, amount float64, address string, memo string) string {
	params := TestnetChainParams()

	keystoreConfig := key.NewKeystoreConfig(
		params.ChainID,
		params.ChainName,
		params.BIP44CoinType,
		params.LedgerName,
		params.Symbol,
	)

	return keystoreConfig.GenerateLedgerHeaders(operation, amount, address, memo)
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

// GetNetworkName returns the human-readable network name
func (p *ChainParameters) GetNetworkName() string {
	switch p.ChainID {
	case 7331:
		return "Sphinx Mainnet" // Always return "Sphinx Mainnet" for chain ID 7331
	case 17331:
		return "Sphinx Testnet"
	case 27331:
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

// GetKeystoreConfig returns the appropriate keystore configuration for these chain parameters
func (p *ChainParameters) GetKeystoreConfig() *key.KeystoreConfig {
	switch p.ChainID {
	case 7331:
		if p.ChainName == "Sphinx Mainnet" {
			return key.GetMainnetKeystoreConfig()
		}
		return key.GetDevnetKeystoreConfig()
	case 17331:
		return key.GetTestnetKeystoreConfig()
	case 27331:
		// For regtest, create a custom config
		return key.NewKeystoreConfig(
			p.ChainID,
			p.ChainName,
			p.BIP44CoinType,
			p.LedgerName,
			p.Symbol,
		)
	default:
		return key.GetMainnetKeystoreConfig()
	}
}
