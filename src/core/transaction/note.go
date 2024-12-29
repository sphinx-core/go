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
	"math/big"
	"strings"
	"time"
)

// Note represents the receipt or note of a transaction.
type Note struct {
	To        string  `json:"to"`        // Recipient (Bob's wallet address)
	From      string  `json:"from"`      // Sender (Alice's wallet address)
	Fee       float64 `json:"fee"`       // Transaction fee
	Storage   string  `json:"storage"`   // Storage information for the transaction
	Timestamp int64   `json:"timestamp"` // Timestamp when the transaction was created (in int64 format)
}

// NewNote creates a new note with the provided details.
func NewNote(to, from string, fee float64, storage string) (*Note, error) {
	// Validate wallet addresses to ensure they are in the correct format
	if err := validateAddress(to); err != nil {
		return nil, err
	}

	if err := validateAddress(from); err != nil {
		return nil, err
	}

	return &Note{
		To:        to,
		From:      from,
		Fee:       fee,
		Storage:   storage,
		Timestamp: time.Now().Unix(), // Storing timestamp as int64
	}, nil
}

// validateAddress checks if the address is in the correct format (26-62 alphanumeric characters).
func validateAddress(address string) error {

	// Base58 address validation (starts with 'x' and length between 26 and 62 characters)
	if len(address) >= 26 && len(address) <= 62 && strings.HasPrefix(address, "x") && isAlphanumeric(address[1:]) {
		// Check if the address starts with 'x' and is alphanumeric (excluding the 'x')
		return nil
	}

	return errors.New("invalid address format. Must be an alphanumeric address with 26-62 characters, starting with 'x'")
}

// isAlphanumeric checks if the string contains only alphanumeric characters.
func isAlphanumeric(s string) bool {
	for _, char := range s {
		if !isAlphanumericChar(char) {
			return false
		}
	}
	return true
}

// isAlphanumericChar checks if the character is alphanumeric.
func isAlphanumericChar(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// ToTransaction converts a Note to a Transaction.
func (n *Note) ToTxs(nonce uint64, gasLimit, gasPrice *big.Int) *Transaction {
	// Convert Fee to Amount (using Fee as amount for simplicity)
	amount := big.NewInt(int64(n.Fee))

	// Create the transaction from the Note
	return &Transaction{
		Sender:    n.From,
		Receiver:  n.To,
		Amount:    amount,
		GasLimit:  gasLimit,
		GasPrice:  gasPrice,
		Timestamp: n.Timestamp, // Passing the int64 timestamp directly
		Nonce:     nonce,
	}
}
