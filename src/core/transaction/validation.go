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

// go/src/core/transaction/validation.go
package types

import (
	"errors"
	"fmt"
	"strings"

	"github.com/sphinx-core/go/src/common"
)

// NewValidator creates a new Validator instance that holds the sender and recipient addresses.
func NewValidator(senderAddress, recipientAddress string) *Validator {
	return &Validator{
		senderAddress:    senderAddress,    // Initialize sender address.
		recipientAddress: recipientAddress, // Initialize recipient address.
	}
}

// ValidateSpendability checks if a UTXO is spendable at a given height.
func ValidateSpendability(set *UTXOSet, txID string, index int, height uint64) bool {
	out := Outpoint{TxID: txID, Index: index}
	return set.IsSpendable(out, height)
}

// Validate method checks if the provided note is valid.
func (v *Validator) Validate(note *Note) error {
	if note.From != v.senderAddress {
		return fmt.Errorf("invalid sender, expected %s, got %s", v.senderAddress, note.From)
	}
	if note.To != v.recipientAddress {
		return fmt.Errorf("invalid recipient, expected %s, got %s", v.recipientAddress, note.To)
	}
	if note.Fee <= 0 {
		return fmt.Errorf("invalid fee amount, must be greater than 0")
	}
	if note.Storage == "" {
		return fmt.Errorf("storage information cannot be empty")
	}
	return nil
}

// CreateAddress generates a unique contract address using sender, recipient, and nonce.
func (v *Validator) CreateAddress(nonce int64) (string, error) {
	contractData := fmt.Sprintf("%s-%s-%d", v.senderAddress, v.recipientAddress, nonce)
	hash := common.SpxHash([]byte(contractData))
	address, err := common.Address(hash)
	if err != nil {
		return "", err
	}
	return address, nil
}

// validateAddress checks if the provided address is valid according to specific rules.
func validateAddress(address string) error {
	if len(address) < 26 || len(address) > 62 {
		return errors.New("address length must be between 26 and 62 characters")
	}
	if !strings.HasPrefix(address, "x") {
		return errors.New("address must start with 'x'")
	}
	if !isAlphanumeric(address[1:]) {
		return errors.New("address contains invalid characters")
	}
	return nil
}

// isAlphanumeric checks if the provided string consists solely of alphanumeric characters.
func isAlphanumeric(s string) bool {
	for _, char := range s {
		if !isAlphanumericChar(char) {
			return false
		}
	}
	return true
}

// isAlphanumericChar checks if a single character is alphanumeric.
func isAlphanumericChar(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
