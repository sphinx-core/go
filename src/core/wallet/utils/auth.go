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
	"fmt"

	"golang.org/x/crypto/sha3"
)

// GenerateHMAC generates a keyed-hash message authentication code (HMAC) using SHA3-256.
func GenerateHMAC(data []byte, key string) ([]byte, error) {
	// Initialize a new HMAC hash object with SHA3-256 (Keccak-256) and the provided key
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
	// Generate the actual HMAC for the given data and key
	actualHMAC, err := GenerateHMAC(data, key)
	if err != nil {
		// Return false and an error message if HMAC generation fails
		return false, fmt.Errorf("failed to generate HMAC: %v", err)
	}

	// Compare the generated HMAC with the expected one using hmac.Equal (constant-time comparison)
	if !hmac.Equal(actualHMAC, expectedHMAC) {
		// Return false if the HMACs do not match
		return false, nil
	}

	// Return true if the HMACs match
	return true, nil
}
