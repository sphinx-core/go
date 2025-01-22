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

package sigproof

import (
	"bytes"
	"errors"
	"sync"

	"github.com/sphinx-core/go/src/common"
)

// Define a global mutex to protect access to shared memory
var mu sync.Mutex

// GenerateSigProof generates a hash of the signature parts as a proof
func GenerateSigProof(sigParts [][]byte, leaves [][]byte) ([]byte, error) {
	// Lock the mutex to ensure no concurrent access to shared memory
	mu.Lock()
	defer mu.Unlock() // Ensure the mutex is unlocked after the operation

	// Check if signature parts are not empty
	if len(sigParts) == 0 {
		return nil, errors.New("no signature parts provided")
	}

	// Generate the hash of the signature parts using the provided leaves
	hash := generateHashFromParts(sigParts, leaves)

	// Return the resulting hash as proof
	return hash, nil
}

// generateHashFromParts creates a combined hash of the given signature parts and data from the leaves
func generateHashFromParts(parts [][]byte, leaves [][]byte) []byte {
	// Concatenate all parts into a single slice
	var combined []byte
	for _, part := range parts {
		combined = append(combined, part...)
	}

	// Append the leaves to the combined data
	for _, leaf := range leaves {
		combined = append(combined, leaf...)
	}

	// Now use the SpxHash from the common package to hash the combined data
	hash := common.SpxHash(combined)

	return hash
}

// VerifySigProof compares the generated hash with the expected proof hash
func VerifySigProof(proofHash, generatedHash []byte) bool {
	// Lock the mutex to ensure no concurrent access to shared memory during verification
	mu.Lock()
	defer mu.Unlock()

	// Compare the proof hash with the generated hash
	return bytes.Equal(proofHash, generatedHash)
}
