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
	"fmt"
	"math/big"
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
func NewNote(to, from string, fee float64, storage, key string) (*Note, error) {
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
	mac, err := generateMAC(note, key)
	if err != nil {
		// If an error occurs while generating the MAC, return the error
		return nil, err
	}

	// Step 4: Assign the generated MAC to the Note struct.
	note.MAC = mac

	// Step 5: Return the newly created Note with the MAC included.
	return note, nil
}

// generateMAC generates a Message Authentication Code (MAC) for a given Note using a secret key.
// The MAC ensures the integrity and authenticity of the Note's data.
func generateMAC(note *Note, key string) (string, error) {
	// Step 1: Construct a message string by concatenating the key with the Note's fields.
	// The message format: key + To + From + Fee + Storage + Timestamp.
	message := key +
		note.To + // Recipient's address
		note.From + // Sender's address
		fmt.Sprintf("%f", note.Fee) + // Fee (converted to a string)
		note.Storage + // Storage metadata
		fmt.Sprintf("%d", note.Timestamp) // Timestamp (converted to a string)

	// Step 2: Convert the constructed message into a byte slice.
	messageBytes := []byte(message)

	// Step 3: Compute the hash of the message using the SphinxHash function.
	hash := common.SpxHash(messageBytes)

	// Step 4: Encode the hash into a hexadecimal string to make it human-readable.
	mac := hex.EncodeToString(hash)

	// Step 5: Return the generated MAC.
	return mac, nil
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
