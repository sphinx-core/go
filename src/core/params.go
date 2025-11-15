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

// GetSphinxChainParams returns the mainnet parameters for Sphinx blockchain
// GetSphinxChainParams returns the mainnet parameters for Sphinx blockchain
// Now accepts genesisHash as parameter
func GetSphinxChainParams(genesisHash string) *SphinxChainParameters {
	return &SphinxChainParameters{
		ChainID:       7331,
		ChainName:     "Sphinx",
		Symbol:        "SPX",
		GenesisTime:   1731375284,
		GenesisHash:   genesisHash,
		Version:       "1.0.0",
		MagicNumber:   0x53504858,
		DefaultPort:   32307,
		BIP44CoinType: 7331,
		LedgerName:    "Sphinx",
		Denominations: map[string]*big.Int{
			"nSPX": big.NewInt(1e0),
			"gSPX": big.NewInt(1e9),
			"SPX":  big.NewInt(1e18),
		},

		// Block size limits (NEW)
		MaxBlockSize:       2 * 1024 * 1024,      // 2MB max block size
		MaxTransactionSize: 100 * 1024,           // 100KB max transaction size
		TargetBlockSize:    1 * 1024 * 1024,      // 1MB target block size
		BlockGasLimit:      big.NewInt(10000000), // 10 million gas
	}
}
