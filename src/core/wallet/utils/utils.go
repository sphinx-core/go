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

// In-memory storage for chaining data - stores both fingerprint and chain code
var memoryStore = make(map[string]struct {
	Fingerprint []byte
	ChainCode   []byte
})

// EncodeBase32 encodes a byte slice into a Base32 string without padding
func EncodeBase32(data []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
}

// DecodeBase32 decodes a Base32 string into a byte slice
func DecodeBase32(base32Str string) ([]byte, error) {
	decoded, err := base32.StdEncoding.DecodeString(base32Str)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base32 string: %v", err)
	}
	return decoded, nil
}

// GenerateFingerprintAndChainCode generates the fingerprint (root hash) and chain code
// It stores both the fingerprint and chain code in memory for future use.
func GenerateChainCode(combinedParts []byte, hashedPasskey []byte) ([]byte, []byte, error) {
	// Combine the provided parts and the hashed passkey to form the key material
	KeyMaterial := append(combinedParts, hashedPasskey...)

	// Generate the fingerprint (root hash) from the key material using the SpxHash function
	fingerprint := common.SpxHash(KeyMaterial)

	// Ensure that the fingerprint is 256 bits (32 bytes)
	if len(fingerprint) != 32 {
		return nil, nil, fmt.Errorf("fingerprint is not 256 bits (32 bytes)")
	}

	// Generate the chain code by combining the original parts and the fingerprint, then hashing it
	chainCode := common.SpxHash(append(combinedParts, fingerprint...))

	// Lock memoryStore to safely store the chain code in memory
	mu.Lock()
	defer mu.Unlock()

	// Store both fingerprint and chain code in memory using the Base32-encoded version of combinedParts as the key
	decodepasskeyStr := EncodeBase32(combinedParts)
	memoryStore[decodepasskeyStr] = struct {
		Fingerprint []byte
		ChainCode   []byte
	}{
		Fingerprint: fingerprint,
		ChainCode:   chainCode,
	}

	// Return the fingerprint and chain code
	return fingerprint, chainCode, nil
}

// VerifyBase32Passkey verifies the fingerprint and checks the chain code in memory
// If the fingerprint and chain code are found, it prints the fingerprint.
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
	storedData, exists := memoryStore[decodepasskeyStr]
	mu.Unlock()

	// If the chain code exists in memory, return the fingerprint and chain code
	if exists {
		// Print the fingerprint once it's verified
		fmt.Printf("Verified Fingerprint: %x\n", storedData.Fingerprint)
		fmt.Printf("Found ChainCode: %x\n", storedData.ChainCode)
		// Return both the fingerprint and chain code
		return true, storedData.Fingerprint, storedData.ChainCode, nil
	} else {
		// If the chain code doesn't exist, generate it
		fingerprint, chainCode, err := GenerateChainCode(decodedPasskey, nil) // Generate fingerprint with the passed key parts
		if err != nil {
			return false, nil, nil, fmt.Errorf("failed to generate fingerprint: %v", err)
		}

		// Print the fingerprint after it is generated
		fmt.Printf("Generated Fingerprint: %x\n", fingerprint)

		// Return the newly generated fingerprint and chain code
		return true, fingerprint, chainCode, nil
	}
}

// VerifyChainCode verifies that the ChainCode stored in memory matches the newly generated ChainCode
func VerifyChainCode(decodepasskey []byte, fingerprint []byte) (bool, error) {
	mu.Lock() // Lock memory access for thread-safety
	defer mu.Unlock()

	// Encode the decoded passkey into Base32 format to use as the key
	decodepasskeyStr := EncodeBase32(decodepasskey)

	// Look up the stored chain code for the passkey
	storedData, exists := memoryStore[decodepasskeyStr]
	if !exists {
		return false, fmt.Errorf("chain code not found for the provided passkey")
	}

	// Re-generate the chain code by combining the passkey and fingerprint and hashing the result
	combined := append(decodepasskey, fingerprint...)
	newChainCode := common.SpxHash(combined)

	// Compare the newly generated chain code with the stored one
	if string(storedData.ChainCode) == string(newChainCode) {
		return true, nil // Verification successful
	}

	// If the chain codes don't match, return verification failure
	return false, fmt.Errorf("chain code verification failed")
}
