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

// ValidateSpendability checks if a UTXO (Unspent Transaction Output) is spendable at a given height.
func ValidateSpendability(set *UTXOSet, txID string, index int, height uint64) bool {
	// Create an Outpoint struct using the transaction ID and index of the output.
	out := Outpoint{TxID: txID, Index: index}

	// Call IsSpendable method on UTXOSet to check if this output is spendable at the given block height.
	return set.IsSpendable(out, height)
}

// Validate method checks if the provided note is valid.
func (v *Validator) Validate(note *Note) error {
	// Check if the sender address matches the expected sender address.
	if note.From != v.senderAddress {
		// If the sender is incorrect, return an error with a formatted message.
		return fmt.Errorf("invalid sender, expected %s, got %s", v.senderAddress, note.From)
	}

	// Check if the recipient address matches the expected recipient address.
	if note.To != v.recipientAddress {
		// If the recipient is incorrect, return an error with a formatted message.
		return fmt.Errorf("invalid recipient, expected %s, got %s", v.recipientAddress, note.To)
	}

	// Validate the fee amount to ensure it's greater than 0.
	if note.Fee <= 0 {
		return fmt.Errorf("invalid fee amount, must be greater than 0")
	}

	// Ensure the storage information is provided.
	if note.Storage == "" {
		return fmt.Errorf("storage information cannot be empty")
	}

	// If all checks pass, return nil indicating the note is valid.
	return nil
}

// CreateAddress generates a unique contract address using sender, recipient, and nonce.
func (v *Validator) CreateAddress(nonce int64) (string, error) {
	// Combine the sender address, recipient address, and nonce into a single string.
	contractData := fmt.Sprintf("%s-%s-%d", v.senderAddress, v.recipientAddress, nonce)

	// Use the common.SpxHash function to hash the combined contract data.
	hash := common.SpxHash([]byte(contractData))

	// Generate a contract address using the common.Address function, which manipulates the hash.
	address, err := common.Address(hash)
	if err != nil {
		// Return an error if generating the address fails.
		return "", err
	}

	// Return the generated contract address.
	return address, nil
}

// validateAddress checks if the provided address is valid according to specific rules.
func validateAddress(address string) error {
	// Check if the address length is within the valid range (26 to 62 characters).
	if len(address) < 26 || len(address) > 62 {
		return errors.New("address length must be between 26 and 62 characters")
	}

	// Ensure the address starts with the prefix 'x'.
	if !strings.HasPrefix(address, "x") {
		return errors.New("address must start with 'x'")
	}

	// Verify that the remainder of the address contains only alphanumeric characters.
	if !isAlphanumeric(address[1:]) {
		return errors.New("address contains invalid characters")
	}

	// Return nil if all validations pass (address is valid).
	return nil
}

// isAlphanumeric checks if the provided string consists solely of alphanumeric characters.
func isAlphanumeric(s string) bool {
	// Iterate through each character in the string.
	for _, char := range s {
		// If any character is not alphanumeric, return false.
		if !isAlphanumericChar(char) {
			return false
		}
	}
	// If all characters are alphanumeric, return true.
	return true
}

// isAlphanumericChar checks if a single character is alphanumeric (a digit or letter).
func isAlphanumericChar(c rune) bool {
	// Check if the character is a digit ('0'-'9') or a letter ('a'-'z', 'A'-'Z').
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
