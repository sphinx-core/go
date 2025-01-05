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
func GenerateHMAC(data []byte, key string) ([]byte, error) {
	// Initialize a new HMAC hash object with SHA3-512 (Keccak-512) and the provided key
	h := hmac.New(sha3.NewLegacyKeccak512, []byte(key))
	_, err := h.Write(data)
	if err != nil {
		// Return an error if the data couldn't be written to the HMAC object
		return nil, fmt.Errorf("failed to write data to HMAC: %v", err)
	}
	// Return the HMAC result (sum of the data)
	return h.Sum(nil), nil
}

// VerifyHMAC verifies whether the HMAC of the given data matches the expected HMAC value.
func VerifyHMAC(data []byte, key string, expectedHMAC []byte) (bool, error) {
	// Attempt to decode the key from Base32 if it is Base32 encoded
	decodedKey, err := base32.StdEncoding.DecodeString(key)
	if err == nil {
		// If Base32 decoding works, use the decoded key for HMAC
		actualHMAC, err := GenerateHMAC(data, string(decodedKey))
		if err != nil {
			return false, fmt.Errorf("failed to generate HMAC with Base32 decoded key: %v", err)
		}

		// Compare the actual HMAC with the expected one using constant-time comparison
		if !hmac.Equal(actualHMAC, expectedHMAC) {
			return false, nil // HMACs don't match
		}
		return true, nil // HMACs match
	}

	// If Base32 decoding fails, try to decode the key from hex if it is in hex format
	var keyBytes []byte
	if isHex(key) {
		keyBytes, err = hex.DecodeString(key)
		if err != nil {
			return false, fmt.Errorf("failed to decode hex key: %v", err)
		}
		// Generate HMAC with the decoded hex key
		actualHMAC, err := GenerateHMAC(data, string(keyBytes))
		if err != nil {
			return false, fmt.Errorf("failed to generate HMAC with hex decoded key: %v", err)
		}

		// Compare the actual HMAC with the expected one
		if !hmac.Equal(actualHMAC, expectedHMAC) {
			return false, nil // HMACs don't match
		}
		return true, nil // HMACs match
	}

	// If the key is neither Base32 nor hex, proceed with the raw key as it is
	actualHMAC, err := GenerateHMAC(data, key)
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
