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

package utils

import (
	"encoding/base32"
	"fmt"
	"sync"

	"github.com/sphinx-core/go/src/common"
)

// Mutex to protect access to memoryStore - ensures thread-safe access
var mu sync.Mutex

// In-memory storage for chaining data - stores chain codes with passkey identifiers
// memoryStore is a map that stores the chain code for each passkey (Base32-encoded version of the passkey).
var memoryStore = make(map[string][]byte)

// EncodeBase32 encodes a byte slice into a Base32 string without padding
// This function converts the input byte slice to a Base32-encoded string representation
// It uses standard Base32 encoding without padding (no '=' characters at the end).
func EncodeBase32(data []byte) string {
	// Using standard Base32 encoding without padding
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
}

// DecodeBase32 decodes a Base32 string into a byte slice
// This function takes a Base32-encoded string and decodes it back into a byte slice
// Returns the decoded byte slice or an error if decoding fails.
func DecodeBase32(base32Str string) ([]byte, error) {
	decoded, err := base32.StdEncoding.DecodeString(base32Str)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base32 string: %v", err)
	}
	return decoded, nil
}

// GenerateRootHash generates a root hash (fingerprint) and the associated chain code
// It combines the decoded parts of a passkey with a hashed passkey and generates the chain code
// The fingerprint is the hashed result of the key material
// The chain code is derived from combining the fingerprint and the original parts
// Generates and stores the fingerprint and chain code in memory for future use.
func GenerateRootHash(combinedParts []byte, hashedPasskey []byte) ([]byte, []byte, error) {
	// Combine the provided parts and the hashed passkey to form the key material
	KeyMaterial := append(combinedParts, hashedPasskey...)
	fmt.Printf("Final Key Material: %x\n", KeyMaterial)

	// Generate the fingerprint (root hash) from the key material using the SpxHash function
	fingerprint := common.SpxHash(KeyMaterial)

	// Ensure that the fingerprint is 256 bits (32 bytes)
	if len(fingerprint) != 32 {
		return nil, nil, fmt.Errorf("root hash is not 256 bits (32 bytes)")
	}

	// Generate the chain code by combining the original parts and the fingerprint, then hashing it
	chainCode := common.SpxHash(append(combinedParts, fingerprint...))

	// Lock memoryStore to safely store the chain code in memory
	mu.Lock()
	defer mu.Unlock()

	// Store the chain code in memory using the Base32-encoded version of combinedParts as the key
	decodepasskeyStr := EncodeBase32(combinedParts)
	memoryStore[decodepasskeyStr] = chainCode

	// Return the fingerprint and chain code
	return fingerprint, chainCode, nil
}

// VerifyBase32Passkey only derives the fingerprint from the decoded passkey and checks the chain code
// This function verifies if the passkey has been previously stored by decoding the passkey and checking if
// the corresponding chain code is stored in memory. If not, it generates and stores the chain code.
func VerifyBase32Passkey(base32Passkey string) (bool, []byte, []byte, error) {
	// Decode the Base32-encoded passkey into a byte slice
	decodedPasskey, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(base32Passkey)
	if err != nil {
		return false, nil, nil, fmt.Errorf("failed to decode base32 passkey: %v", err)
	}

	// Print the decoded passkey in hexadecimal form for debugging
	fmt.Printf("Decoded Passkey: %x\n", decodedPasskey)

	// Check if the chain code exists for the decoded passkey in memory
	decodepasskeyStr := EncodeBase32(decodedPasskey)
	mu.Lock() // Lock memory access for thread-safety
	storedChainCode, exists := memoryStore[decodepasskeyStr]
	mu.Unlock()

	// If the chain code exists in memory, return it along with the fingerprint
	if exists {
		fmt.Printf("Found ChainCode: %x\n", storedChainCode)
		// Assuming the fingerprint is already stored, return both the fingerprint and chain code
		// The fingerprint and chain code are stored in the same entry in memory for simplicity.
		return true, storedChainCode, storedChainCode, nil // Return stored chain code as both fingerprint and chain code
	} else {
		// If the chain code doesn't exist, generate it
		// It should only happen once, or else retrieve it from memory if needed
		rootHash, chainCode, err := GenerateRootHash(decodedPasskey, nil) // Generate root hash with the passed key parts
		if err != nil {
			return false, nil, nil, fmt.Errorf("failed to generate root hash: %v", err)
		}

		// Return the newly generated root hash and chain code
		return true, rootHash, chainCode, nil
	}
}

// VerifyChainCode verifies that the ChainCode stored in memory matches the newly generated ChainCode
// It compares the stored chain code with the newly generated one based on the passkey and fingerprint
// If they match, the verification is successful; otherwise, it fails.
func VerifyChainCode(decodepasskey []byte, fingerprint []byte) (bool, error) {
	mu.Lock() // Lock memory access for thread-safety
	defer mu.Unlock()

	// Encode the decoded passkey into Base32 format to use as the key
	decodepasskeyStr := EncodeBase32(decodepasskey)

	// Look up the stored chain code for the passkey
	storedChainCode, exists := memoryStore[decodepasskeyStr]
	if !exists {
		return false, fmt.Errorf("chain code not found for the provided passkey")
	}

	// Re-generate the chain code by combining the passkey and fingerprint and hashing the result
	combined := append(decodepasskey, fingerprint...)
	newChainCode := common.SpxHash(combined)

	// Compare the newly generated chain code with the stored one
	if string(storedChainCode) == string(newChainCode) {
		return true, nil // Verification successful
	}

	// If the chain codes don't match, return verification failure
	return false, fmt.Errorf("chain code verification failed")
}
