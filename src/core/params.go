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
