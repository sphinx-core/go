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

package multisig

import (
	"fmt"
	"log"
)

// GetIndex returns the index of a given public key (pk) in the list of participant keys.
// It is used to find the position of the public key in the keys array.
func (m *MultisigManager) GetIndex(pk []byte) int {
	m.mu.RLock()         // Lock for reading to ensure thread-safety while accessing the keys
	defer m.mu.RUnlock() // Unlock after the operation is complete

	// Loop through the list of participant keys to find the index of the provided public key
	for i, key := range m.storedPK {
		if fmt.Sprintf("%x", key) == fmt.Sprintf("%x", pk) {
			return i // Return the index if the key matches
		}
	}
	return -1 // Return -1 if the key is not found
}

// AddSig adds a signature to the multisig at the given index corresponding to a participant's public key.
// This method is used to record a signature from a participant in the multisig.
func (m *MultisigManager) AddSig(index int, sig []byte) error {
	m.mu.Lock()         // Lock for writing to ensure thread-safety while modifying state
	defer m.mu.Unlock() // Unlock after the operation is complete

	if index < 0 || index >= len(m.storedPK) {
		log.Printf("Invalid index %d, keys length: %d", index, len(m.storedPK))
		return fmt.Errorf("invalid index %d", index)
	}

	// Store the signature indexed by the participant's public key (converted to hex string)
	m.signatures[fmt.Sprintf("%x", m.storedPK[index])] = sig
	return nil
}

// AddSigFromPubKey adds a signature to the multisig based on the provided public key (pubKey).
// This method allows for signing directly using the public key instead of the index.
func (m *MultisigManager) AddSigFromPubKey(pubKey []byte, sig []byte) error {
	// Retrieve the index for the given public key
	index := m.GetIndex(pubKey)
	if index == -1 {
		// Return an error if the public key is not found in the list of keys
		return fmt.Errorf("public key not found in multisig keys")
	}

	// Call the AddSig method to add the signature at the correct index
	return m.AddSig(index, sig)
}
