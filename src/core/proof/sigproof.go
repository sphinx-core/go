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

var (
	mu          sync.Mutex
	storedProof []byte // Global variable for storing the proof
)

// GenerateSigProof generates a hash of the signature parts, Merkle leaves, and public key as a proof
func GenerateSigProof(sigParts [][]byte, leaves [][]byte, pkBytes []byte) ([]byte, error) {
	mu.Lock()
	defer mu.Unlock()

	if len(sigParts) == 0 {
		return nil, errors.New("no signature parts provided")
	}

	// Include pkBytes in the proof generation
	hash := generateHashFromParts(sigParts, leaves, pkBytes)
	return hash, nil
}

// generateHashFromParts creates a combined hash of the given signature parts, Merkle leaves, and public key
func generateHashFromParts(parts [][]byte, leaves [][]byte, pkBytes []byte) []byte {
	var combined []byte
	for _, part := range parts {
		combined = append(combined, part...)
	}
	for _, leaf := range leaves {
		combined = append(combined, leaf...)
	}
	// Append the public key bytes
	combined = append(combined, pkBytes...)

	return common.SpxHash(combined)
}

// VerifySigProof compares the generated hash with the expected proof hash
func VerifySigProof(proofHash, generatedHash []byte) bool {
	mu.Lock()
	defer mu.Unlock()
	return bytes.Equal(proofHash, generatedHash)
}

// SetStoredProof safely sets the stored proof
func SetStoredProof(proof []byte) {
	mu.Lock()
	defer mu.Unlock()
	storedProof = proof
}

// GetStoredProof safely retrieves the stored proof
func GetStoredProof() []byte {
	mu.Lock()
	defer mu.Unlock()
	return storedProof
}
