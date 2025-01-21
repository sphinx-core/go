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

// Validator validates the transaction note.
type Validator struct {
	senderAddress    string
	recipientAddress string
}

// NewValidator creates a new Validator instance.
func NewValidator(senderAddress, recipientAddress string) *Validator {
	return &Validator{
		senderAddress:    senderAddress,
		recipientAddress: recipientAddress,
	}
}

// Validate checks if the note is valid.
func (v *Validator) Validate(note *Note) error {
	// Check if Alice is the sender and Bob is the recipient
	if note.From != v.senderAddress {
		return fmt.Errorf("invalid sender, expected %s, got %s", v.senderAddress, note.From)
	}
	if note.To != v.recipientAddress {
		return fmt.Errorf("invalid recipient, expected %s, got %s", v.recipientAddress, note.To)
	}
	// Additional validation checks like fee, storage, etc. can be added here
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
	// Combine the sender address, recipient address, and nonce into a single string
	contractData := fmt.Sprintf("%s-%s-%d", v.senderAddress, v.recipientAddress, nonce)

	// Use common.SpxHash to get the hash for the combined contract data
	hash := common.SpxHash([]byte(contractData))

	// Use the common.Address function to manipulate the contract address
	address, err := common.Address(hash)
	if err != nil {
		return "", err
	}

	// Return the manipulated contract address
	return address, nil
}

// validateAddress validates a wallet address to ensure it adheres to specific rules.
func validateAddress(address string) error {
	// Step 1: Check if the address length is within the valid range (26 to 62 characters).
	if len(address) < 26 || len(address) > 62 {
		return errors.New("address length must be between 26 and 62 characters")
	}

	// Step 2: Ensure the address starts with the prefix 'x'.
	if !strings.HasPrefix(address, "x") {
		return errors.New("address must start with 'x'")
	}

	// Step 3: Verify that the remainder of the address contains only alphanumeric characters.
	if !isAlphanumeric(address[1:]) {
		return errors.New("address contains invalid characters")
	}

	// Step 4: Return nil if all validations pass.
	return nil
}

// isAlphanumeric checks if the provided string consists solely of alphanumeric characters.
func isAlphanumeric(s string) bool {
	// Step 1: Iterate through each character in the string.
	for _, char := range s {
		// Step 2: If any character is not alphanumeric, return false.
		if !isAlphanumericChar(char) {
			return false
		}
	}
	// Step 3: If all characters are alphanumeric, return true.
	return true
}

// isAlphanumericChar checks if a single character is alphanumeric (a digit or letter).
func isAlphanumericChar(c rune) bool {
	// Step 1: Check if the character is between '0' and '9' (a digit).
	// Step 2: Check if the character is between 'a' and 'z' or 'A' and 'Z' (a letter).
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
