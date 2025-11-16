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

// go/src/core/params.go
package core

import (
	"fmt"
	"math/big"
	"time"

	"github.com/sphinx-core/go/src/pool"
)

// ChainParamsProvider defines an interface to get chain parameters without import cycle
type ChainParamsProvider interface {
	GetChainParams() *SphinxChainParameters
	GetWalletDerivationPaths() map[string]string
}

// Mock implementation for storage package to use
type MockChainParamsProvider struct {
	params *SphinxChainParameters
}

func (m *MockChainParamsProvider) GetChainParams() *SphinxChainParameters {
	return m.params
}

func (m *MockChainParamsProvider) GetWalletDerivationPaths() map[string]string {
	return map[string]string{
		"BIP44":  fmt.Sprintf("m/44'/%d'/0'/0/0", m.params.BIP44CoinType),
		"BIP49":  fmt.Sprintf("m/49'/%d'/0'/0/0", m.params.BIP44CoinType),
		"BIP84":  fmt.Sprintf("m/84'/%d'/0'/0/0", m.params.BIP44CoinType),
		"Ledger": fmt.Sprintf("m/44'/%d'/0'", m.params.BIP44CoinType),
		"Trezor": fmt.Sprintf("m/44'/%d'/0'/0/0", m.params.BIP44CoinType),
	}
}

// GetSphinxChainParams returns the mainnet parameters
func GetSphinxChainParams(genesisHash string) *SphinxChainParameters {
	return &SphinxChainParameters{
		// Network Identification
		ChainID:       7331,
		ChainName:     "Sphinx", // Mainnet name
		Symbol:        "SPX",
		GenesisTime:   1731375284,
		GenesisHash:   genesisHash,
		Version:       "1.0.0",
		MagicNumber:   0x53504858,
		DefaultPort:   32307,
		BIP44CoinType: 7331, // Mainnet uses 7331
		LedgerName:    "Sphinx",
		Denominations: map[string]*big.Int{
			"nSPX": big.NewInt(1e0),
			"gSPX": big.NewInt(1e9),
			"SPX":  big.NewInt(1e18),
		},

		// Block Configuration
		MaxBlockSize:       2 * 1024 * 1024,      // 2MB max block size
		MaxTransactionSize: 100 * 1024,           // 100KB max transaction size
		TargetBlockSize:    1 * 1024 * 1024,      // 1MB target block size
		BlockGasLimit:      big.NewInt(10000000), // 10 million gas

		// Mempool Configuration
		MempoolConfig: GetDefaultMempoolConfig(),

		// Consensus Configuration
		ConsensusConfig: GetDefaultConsensusConfig(),

		// Performance Configuration
		PerformanceConfig: GetDefaultPerformanceConfig(),
	}
}

// GetDefaultMempoolConfig returns the default mempool configuration
func GetDefaultMempoolConfig() *pool.MempoolConfig {
	return &pool.MempoolConfig{
		MaxSize:           10000,
		MaxBytes:          100 * 1024 * 1024, // 100MB
		MaxTxSize:         100 * 1024,        // 100KB
		BlockGasLimit:     big.NewInt(10000000),
		ValidationTimeout: 30 * time.Second,
		ExpiryTime:        24 * time.Hour,
		MaxBroadcastSize:  5000,
		MaxPendingSize:    5000,
	}
}

// GetDefaultConsensusConfig returns the default consensus configuration
func GetDefaultConsensusConfig() *ConsensusConfig {
	return &ConsensusConfig{
		BlockTime:        10 * time.Second,
		EpochLength:      100,
		ValidatorSetSize: 21,
		MaxValidators:    100,
		MinStakeAmount:   big.NewInt(1000000000000000000), // 1 SPX
		UnbondingPeriod:  7 * 24 * time.Hour,              // 7 days
		SlashingEnabled:  true,
		DoubleSignSlash:  big.NewInt(500000000000000000), // 0.5 SPX
	}
}

// GetDefaultPerformanceConfig returns the default performance configuration
func GetDefaultPerformanceConfig() *PerformanceConfig {
	return &PerformanceConfig{
		MaxConcurrentValidations: 100,
		ValidationTimeout:        30 * time.Second,
		CacheSize:                10000,
		PruningInterval:          5 * time.Minute,
		MaxPeers:                 50,
		SyncBatchSize:            100,
	}
}

// GetTestnetChainParams returns testnet parameters
func GetTestnetChainParams(genesisHash string) *SphinxChainParameters {
	params := GetSphinxChainParams(genesisHash)
	params.ChainName = "Sphinx Testnet"
	params.ChainID = 17331 // Different chain ID
	params.DefaultPort = 32308
	params.BIP44CoinType = 1 // Same as devnet
	params.LedgerName = "Sphinx Testnet"

	// Testnet-specific adjustments
	params.MaxBlockSize = 4 * 1024 * 1024       // 4MB for testing
	params.BlockGasLimit = big.NewInt(20000000) // 20 million gas for testing

	// Faster block times for testing
	params.ConsensusConfig.BlockTime = 5 * time.Second
	params.ConsensusConfig.EpochLength = 50

	return params
}

// GetDevnetChainParams returns development network parameters
func GetDevnetChainParams(genesisHash string) *SphinxChainParameters {
	params := GetSphinxChainParams(genesisHash)
	params.ChainName = "Sphinx Devnet"
	params.ChainID = 7331 // Same as mainnet but different name
	params.DefaultPort = 32309
	params.BIP44CoinType = 1 // Different from mainnet (7331)
	params.LedgerName = "Sphinx Devnet"

	// Development-specific adjustments
	params.MaxBlockSize = 8 * 1024 * 1024       // 8MB for development
	params.BlockGasLimit = big.NewInt(50000000) // 50 million gas for development

	// Very fast block times for development
	params.ConsensusConfig.BlockTime = 2 * time.Second
	params.ConsensusConfig.EpochLength = 10
	params.ConsensusConfig.MinStakeAmount = big.NewInt(1000000000000000) // Lower stake for testing

	return params
}

// GetMempoolConfigFromChainParams extracts mempool config from chain params
func GetMempoolConfigFromChainParams(chainParams *SphinxChainParameters) *pool.MempoolConfig {
	if chainParams == nil || chainParams.MempoolConfig == nil {
		return GetDefaultMempoolConfig()
	}
	return chainParams.MempoolConfig
}

// ValidateChainParams validates the chain parameters
func ValidateChainParams(params *SphinxChainParameters) error {
	if params == nil {
		return fmt.Errorf("chain parameters cannot be nil")
	}

	if params.ChainID == 0 {
		return fmt.Errorf("chain ID cannot be zero")
	}

	if params.MaxBlockSize == 0 {
		return fmt.Errorf("max block size cannot be zero")
	}

	if params.MaxTransactionSize > params.MaxBlockSize {
		return fmt.Errorf("max transaction size cannot exceed max block size")
	}

	if params.BlockGasLimit == nil || params.BlockGasLimit.Cmp(big.NewInt(0)) <= 0 {
		return fmt.Errorf("block gas limit must be positive")
	}

	if params.MempoolConfig != nil {
		if params.MempoolConfig.MaxTxSize > params.MaxTransactionSize {
			return fmt.Errorf("mempool max transaction size cannot exceed chain max transaction size")
		}
	}

	return nil
}

// GetNetworkName returns human-readable network name
func (p *SphinxChainParameters) GetNetworkName() string {
	switch p.ChainID {
	case 7331:
		if p.ChainName == "Sphinx Devnet" {
			return "Sphinx Devnet"
		}
		return "Sphinx Mainnet"
	case 17331:
		return "Sphinx Testnet"
	default:
		return "Sphinx Devnet"
	}
}

// IsMainnet returns true if this is mainnet configuration
func (p *SphinxChainParameters) IsMainnet() bool {
	return p.ChainID == 7331 && p.ChainName == "Sphinx"
}

// IsTestnet returns true if this is testnet configuration
func (p *SphinxChainParameters) IsTestnet() bool {
	return p.ChainID == 17331
}

// IsDevnet returns true if this is devnet configuration
func (p *SphinxChainParameters) IsDevnet() bool {
	return p.ChainID == 7331 && p.ChainName == "Sphinx Devnet"
}

// GetStakeDenomination returns the stake denomination
func (p *SphinxChainParameters) GetStakeDenomination() string {
	return "SPX"
}

// ConvertToBaseUnits converts amount to base units (nSPX)
func (p *SphinxChainParameters) ConvertToBaseUnits(amount *big.Int, fromDenom string) (*big.Int, error) {
	multiplier, exists := p.Denominations[fromDenom]
	if !exists {
		return nil, fmt.Errorf("unknown denomination: %s", fromDenom)
	}
	return new(big.Int).Mul(amount, multiplier), nil
}

// ConvertFromBaseUnits converts amount from base units to target denomination
func (p *SphinxChainParameters) ConvertFromBaseUnits(amount *big.Int, toDenom string) (*big.Int, error) {
	multiplier, exists := p.Denominations[toDenom]
	if !exists {
		return nil, fmt.Errorf("unknown denomination: %s", toDenom)
	}
	return new(big.Int).Div(amount, multiplier), nil
}
