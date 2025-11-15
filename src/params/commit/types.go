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

// go/src/params/commit/types.go
package commit

// ChainParameters defines the Sphinx blockchain identification parameters
type ChainParameters struct {
	ChainID       uint64 `json:"chain_id"`
	ChainName     string `json:"chain_name"`
	Symbol        string `json:"symbol"`
	GenesisTime   int64  `json:"genesis_time"`
	GenesisHash   string `json:"genesis_hash"`
	Version       string `json:"version"`
	MagicNumber   uint32 `json:"magic_number"`
	DefaultPort   uint16 `json:"default_port"`
	BIP44CoinType uint32 `json:"bip44_coin_type"`
	LedgerName    string `json:"ledger_name"`
}
