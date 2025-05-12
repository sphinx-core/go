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

package types

import (
	"errors"
	"fmt"
	"math/big"

	params "github.com/sphinx-core/go/src/params/denom"
)

const (
	SPX = 1e18 // 1 SPX equals 1e18 nSPX (10^18), similar to how 1 Ether equals 1e18 wei.
)

// getSPX retrieves the SPX multiplier from the params package
func getSPX() *big.Int {
	return big.NewInt(params.SPX) // 1e18, equivalent to the full SPX token
}

// NewUTXOSet creates a new empty UTXOSet.
func NewUTXOSet() *UTXOSet {
	return &UTXOSet{
		utxos:       make(map[Outpoint]*UTXO), // Initialize the map to store UTXOs
		totalSupply: big.NewInt(0),            // Initialize total supply to 0 (in nSPX)
	}
}

// Add adds a new UTXO to the UTXO set.
func (s *UTXOSet) Add(txID string, txOut Output, index int, coinbase bool, height uint64) error {
	s.mu.Lock()         // Lock the UTXO set for exclusive access during modification
	defer s.mu.Unlock() // Ensure the lock is released when the function returns

	// Convert the maximum supply to big.Int (Multiply params.MaximumSupply by SPX)
	maxSupply := new(big.Int)
	// Correctly handle the two return values from SetString
	_, ok := maxSupply.SetString(fmt.Sprintf("%.0f", params.MaximumSupply*SPX), 10)
	if !ok {
		return errors.New("failed to set maximum supply")
	}

	// Check if adding this UTXO exceeds the maximum supply
	amountInSPX := new(big.Int).SetUint64(txOut.Value) // Convert value to big.Int
	if new(big.Int).Add(s.totalSupply, amountInSPX).Cmp(maxSupply) > 0 {
		return errors.New("exceeding maximum SPX supply")
	}

	// Create an Outpoint for the given transaction ID and output index
	out := Outpoint{TxID: txID, Index: index}
	// Add the UTXO to the set with the provided details
	s.utxos[out] = &UTXO{
		Outpoint: out,
		Value:    txOut.Value,
		Address:  txOut.Address,
		Coinbase: coinbase,
		Height:   height,
		Spent:    false, // Initially, the UTXO is not spent
	}

	// Update the total supply
	s.totalSupply.Add(s.totalSupply, amountInSPX)
	return nil
}

// Spend marks a UTXO as spent.
func (s *UTXOSet) Spend(out Outpoint) {
	s.mu.Lock()         // Lock the UTXO set for exclusive access
	defer s.mu.Unlock() // Ensure the lock is released when the function returns

	// If the UTXO exists in the set, mark it as spent
	if utxo, ok := s.utxos[out]; ok {
		utxo.Spent = true
	}
}

// IsSpendable checks whether a specific UTXO can be spent.
func (s *UTXOSet) IsSpendable(out Outpoint, currentHeight uint64) bool {
	s.mu.RLock()         // Lock the UTXO set for read access (since we are not modifying it)
	defer s.mu.RUnlock() // Ensure the lock is released when the function returns

	// Retrieve the UTXO from the set by its Outpoint
	utxo, ok := s.utxos[out]
	// The UTXO is not spendable if it doesn't exist or is already spent
	if !ok || utxo.Spent {
		return false
	}
	// The UTXO is not spendable if it's a coinbase and hasn't reached maturity (100 blocks)
	if utxo.Coinbase && currentHeight < utxo.Height+100 {
		return false // Coinbase maturity rule: 100 blocks
	}
	// If none of the conditions were violated, the UTXO is spendable
	return true
}
