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
	"crypto/hmac"
	"encoding/base32"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// GenerateHMAC generates a keyed-hash message authentication code (HMAC) using SHA3-512 (Keccak-512).
func GenerateHMAC(data []byte, key []byte) ([]byte, error) {
	h := hmac.New(sha3.NewLegacyKeccak512, key)
	_, err := h.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to write data to HMAC: %v", err)
	}
	return h.Sum(nil), nil
}

// VerifyHMAC verifies whether the HMAC of the given data matches the expected HMAC value.
func VerifyHMAC(data []byte, key string, expectedHMAC []byte) (bool, error) {
	// Check if the key is in hex format
	if isHex(key) {
		keyBytes, err := hex.DecodeString(key)
		if err != nil {
			return false, fmt.Errorf("failed to decode hex key: %v", err)
		}

		// Generate HMAC with the decoded hex key
		actualHMAC, err := GenerateHMAC(data, keyBytes)
		if err != nil {
			return false, fmt.Errorf("failed to generate HMAC with hex decoded key: %v", err)
		}

		// Compare the actual HMAC with the expected one
		if !hmac.Equal(actualHMAC, expectedHMAC) {
			return false, nil // HMACs don't match
		}
		return true, nil // HMACs match
	}

	// If the key is not in hex format, attempt to decode from Base32
	decodedKey, err := base32.StdEncoding.DecodeString(key)
	if err == nil {
		// Generate HMAC with the decoded Base32 key
		actualHMAC, err := GenerateHMAC(data, decodedKey)
		if err != nil {
			return false, fmt.Errorf("failed to generate HMAC with Base32 decoded key: %v", err)
		}

		// Compare the actual HMAC with the expected one
		if !hmac.Equal(actualHMAC, expectedHMAC) {
			return false, nil // HMACs don't match
		}
		return true, nil // HMACs match
	}

	// If the key is neither Base32 nor hex, use the raw key
	actualHMAC, err := GenerateHMAC(data, []byte(key))
	if err != nil {
		return false, fmt.Errorf("failed to generate HMAC with raw key: %v", err)
	}

	// Compare the actual HMAC with the expected one
	if !hmac.Equal(actualHMAC, expectedHMAC) {
		return false, nil // HMACs don't match
	}

	return true, nil // HMACs match
}

// Helper function to check if a string is valid hexadecimal.
func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}

// Function to verify the user during login
func VerifyLogin(userInputBase32, Passphrase string, storedRootHash []byte) (bool, error) {
	// Step 1: Decode the Base32 encoded passkey from the user's input.
	decodedPasskey, err := base32.StdEncoding.DecodeString(userInputBase32)
	if err != nil {
		return false, fmt.Errorf("failed to decode Base32 passkey: %v", err)
	}

	// Step 2: Hash the combination of the decoded passkey and the passphrase (HMAC)
	actualRootHash, err := GenerateHMAC(decodedPasskey, []byte(Passphrase))
	if err != nil {
		return false, fmt.Errorf("failed to generate root hash: %v", err)
	}

	// Step 3: Compare the generated root hash with the stored root hash (fingerprint)
	if !hmac.Equal(actualRootHash, storedRootHash) {
		return false, nil // HMACs don't match
	}

	return true, nil // Login successful
}
