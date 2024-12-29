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
	"math/big"

	"github.com/sphinx-core/go/src/params"
)

// Contract represents the contract between Alice and Bob.
type Contract struct {
	Sender    string   `json:"sender"`
	Receiver  string   `json:"receiver"`
	Amount    *big.Int `json:"amount"` // Use big.Int for the Amount field
	Fee       float64  `json:"fee"`
	Storage   string   `json:"storage"`
	Timestamp int64    `json:"timestamp"` // Changed to int64 to store Unix timestamp
}

// getSPX retrieves the SPX multiplier from the params package
func getSPX() *big.Int {
	return big.NewInt(params.SPX)
}

// CreateContract creates a contract between Alice and Bob based on the validated note.
func CreateContract(note *Note, amountInSPX float64) (*Contract, error) {
	// No need to call Unix() as note.Timestamp is already int64
	timestamp := note.Timestamp // Directly use the int64 timestamp

	// Use getSPX to retrieve the SPX multiplier
	spxMultiplier := getSPX()

	// Multiply the amountInSPX by the SPX multiplier (params.SPX)
	amountInnSPX := amountInSPX * float64(spxMultiplier.Int64())

	// Create a new big.Rat to handle fractional values
	amountRat := new(big.Rat).SetFloat64(amountInnSPX)

	// Convert 1e18 to *big.Rat (as a fraction)
	multiplier := big.NewRat(1e18, 1) // This creates a *big.Rat equivalent to 1e18

	// Multiply the amount by 10^18 (to handle decimals)
	amountRat.Mul(amountRat, multiplier)

	// Convert the resulting big.Rat into a big.Int and round to the nearest integer
	amount := new(big.Int)
	amount.Set(amountRat.Num()) // Use the numerator as the big.Int value

	contract := &Contract{
		Sender:    note.From,
		Receiver:  note.To,
		Amount:    amount, // Set the Amount as *big.Int
		Fee:       note.Fee,
		Storage:   note.Storage,
		Timestamp: timestamp, // Use int64 timestamp here
	}

	// Returning contract and nil error means successful contract creation
	return contract, nil
}
