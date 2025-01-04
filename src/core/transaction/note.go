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
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/sphinx-core/go/src/common"
)

// Note represents the receipt or note of a transaction, with an added MAC (Message Authentication Code).
type Note struct {
	To        string  `json:"to"`        // Recipient's wallet address (Bob's address)
	From      string  `json:"from"`      // Sender's wallet address (Alice's address)
	Fee       float64 `json:"fee"`       // Transaction fee that will be paid
	Storage   string  `json:"storage"`   // Information regarding the storage used for the transaction (e.g., metadata)
	Timestamp int64   `json:"timestamp"` // Timestamp when the transaction was created (in Unix timestamp format)
	MAC       string  `json:"mac"`       // Message Authentication Code to ensure the integrity and authenticity of the note
}

// NewNote creates a new Note instance and computes the MAC for the note.
func NewNote(to, from string, fee float64, storage string) (*Note, error) {
	// Step 1: Validate the sender's and receiver's wallet addresses to ensure they are correctly formatted.
	if err := validateAddress(to); err != nil {
		// If the 'to' address is invalid, return an error
		return nil, err
	}

	if err := validateAddress(from); err != nil {
		// If the 'from' address is invalid, return an error
		return nil, err
	}

	// Step 2: Create a new Note struct with the provided information and the current Unix timestamp.
	note := &Note{
		To:        to,                // Set the recipient's address
		From:      from,              // Set the sender's address
		Fee:       fee,               // Set the transaction fee
		Storage:   storage,           // Set the storage information
		Timestamp: time.Now().Unix(), // Get the current time and store it as a Unix timestamp
	}

	// Step 3: Generate a Message Authentication Code (MAC) for the note to ensure data integrity and authenticity.
	mac, err := generateMAC(note)
	if err != nil {
		// If an error occurs while generating the MAC, return the error
		return nil, err
	}

	// Step 4: Assign the generated MAC to the Note struct.
	note.MAC = mac

	// Step 5: Return the newly created Note with the MAC included.
	return note, nil
}

// generateMAC generates a Message Authentication Code (MAC) using SphinxHash for the given Note.
func generateMAC(note *Note) (string, error) {
	// Step 1: Combine the relevant fields of the note to form a string that will be hashed (excluding the MAC itself).
	message := note.To + note.From + fmt.Sprintf("%f", note.Fee) + note.Storage + fmt.Sprintf("%d", note.Timestamp)

	// Step 2: Convert the message to a byte slice (required by the SpxHash function).
	messageBytes := []byte(message)

	// Step 3: Use the SphinxHash algorithm to generate the hash.
	hash := common.SpxHash(messageBytes)

	// Step 4: Convert the hash to a hexadecimal string.
	mac := hex.EncodeToString(hash)

	// Step 5: Return the generated MAC.
	return mac, nil
}

// validateAddress checks if the address follows a valid format: it should be alphanumeric, have a length between 26 and 62, and start with 'x'.
func validateAddress(address string) error {
	// Step 1: Check that the address length is between 26 and 62 characters and starts with the character 'x'.
	if len(address) >= 26 && len(address) <= 62 && strings.HasPrefix(address, "x") && isAlphanumeric(address[1:]) {
		// If the address is valid, return nil (no error).
		return nil
	}

	// Step 2: If the address doesn't meet the criteria, return an error explaining the problem.
	return errors.New("invalid address format. Must be an alphanumeric address with 26-62 characters, starting with 'x'")
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

// ToTxs converts the current Note instance into a Transaction instance.
func (n *Note) ToTxs(nonce uint64, gasLimit, gasPrice *big.Int) *Transaction {
	// Step 1: Convert the Fee (a float64) to a big integer to be used as the transaction amount.
	amount := big.NewInt(int64(n.Fee))

	// Step 2: Create a new Transaction instance based on the current Note, including the gas details.
	return &Transaction{
		Sender:    n.From,      // Set the sender of the transaction
		Receiver:  n.To,        // Set the receiver of the transaction
		Amount:    amount,      // Set the transaction amount (converted from the Fee)
		GasLimit:  gasLimit,    // Set the gas limit for the transaction
		GasPrice:  gasPrice,    // Set the gas price for the transaction
		Timestamp: n.Timestamp, // Set the timestamp of the note (used in the transaction)
		Nonce:     nonce,       // Set the transaction nonce (used for order in the blockchain)
	}
}
