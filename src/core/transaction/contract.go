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

// getSPX retrieves the SPX multiplier from the params package
func getSPX() *big.Int {
	return big.NewInt(params.SPX) // 1e18, equivalent to the full SPX token
}

// CreateContract creates a contract between Alice and Bob based on the validated note.
// CreateContract creates a contract between Alice and Bob based on the validated note.
func CreateContract(note *Note, amountInSPX float64, set *UTXOSet, txID string, index int, height uint64) (*Contract, error) {
	// Validate amountInSPX to be non-negative
	if amountInSPX < 0 {
		return nil, errors.New("amountInSPX must be non-negative")
	}

	// Validate Timestamp to ensure it’s not unrealistic
	if note.Timestamp <= 0 {
		return nil, errors.New("invalid timestamp")
	}

	// Check if UTXO is spendable
	if !ValidateSpendability(set, txID, index, height) {
		return nil, errors.New("UTXO is not spendable")
	}

	// Add the UTXO to the set and handle any errors
	err := set.Add(txID, *note.Output, index, true, height) // Dereference note.Output
	if err != nil {
		return nil, fmt.Errorf("failed to add UTXO: %v", err)
	}

	// Use getSPX to retrieve the SPX multiplier
	spxMultiplier := getSPX()

	// Convert amountInSPX to a big.Rat to handle fractional amounts
	amountRat := new(big.Rat).SetFloat64(amountInSPX)

	// Multiply the amount by the SPX multiplier
	amountRat.Mul(amountRat, new(big.Rat).SetInt(spxMultiplier))

	// Convert the resulting big.Rat into a big.Int by multiplying by 10^18 to handle decimals
	multiplier := big.NewRat(1e18, 1) // This creates a *big.Rat equivalent to 1e18
	amountRat.Mul(amountRat, multiplier)

	// Convert the resulting big.Rat into a big.Int and round to the nearest integer
	amount := new(big.Int)
	amount.Set(amountRat.Num()) // Use the numerator as the big.Int value

	// Calculate the Fee as a big.Int (assuming the fee is also based on SPX)
	feeRat := new(big.Rat).SetFloat64(note.Fee) // Fee as a float64, convert to big.Rat
	feeRat.Mul(feeRat, amountRat)               // Multiply the fee by the amount
	fee := new(big.Int)
	fee.Set(feeRat.Num()) // Convert fee to big.Int

	contract := &Contract{
		Sender:    note.From,
		Receiver:  note.To,
		Amount:    amount, // Set the Amount as *big.Int
		Fee:       fee,    // Set the Fee as *big.Int
		Storage:   note.Storage,
		Timestamp: note.Timestamp, // Use int64 timestamp here
	}

	// Returning contract and nil error means successful contract creation
	return contract, nil
}
