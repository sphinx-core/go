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
	"fmt"
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

// CreateContract creates a contract between Alice and Bob based on the validated note.
func CreateContract(note *Note, amountInSPX float64) (*Contract, error) {
	// No need to call Unix() as note.Timestamp is already int64
	timestamp := note.Timestamp // Directly use the int64 timestamp

	// Multiply the amountInSPX by the SPX multiplier (params.SPX)
	amountInnSPX := amountInSPX * params.SPX

	// The 10 here is not a hardcoded value representing a specific number of tokens but refers to the base (decimal) of the number being parsed.
	// It's used because big.Int requires the base of the number system when converting a string to a large integer, and for typical token amounts,
	// the base is usually 10 (decimal).
	// Convert the amountInNanoSPX (a float64) to *big.Int
	amount := new(big.Int)
	amount, _ = amount.SetString(fmt.Sprintf("%.0f", amountInnSPX), 10) // Convert to *big.Int

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
