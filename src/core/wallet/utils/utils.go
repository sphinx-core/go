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
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
)

// EncodeBase32 encodes a byte slice into a Base32 string.
func EncodeBase32(data []byte) string {
	// Base32 encode the data
	return base32.StdEncoding.EncodeToString(data)
}

// DecodeBase32 decodes a Base32 string into a byte slice.
func DecodeBase32(base32Str string) ([]byte, error) {
	// Decode the Base32 string
	decoded, err := base32.StdEncoding.DecodeString(base32Str)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base32 string: %v", err)
	}
	return decoded, nil
}

// Generate a root hash that combines the combined parts and the hashed passkey for easy verification
func GenerateRootHash(combinedParts []byte, hashedPasskey []byte) ([]byte, error) {
	// Combine combinedParts and hashedPasskey
	combined := append(combinedParts, hashedPasskey...)

	// Hash the combined data
	rootHash := sha256.Sum256(combined)

	return rootHash[:], nil
}

// Verify that the Base32-encoded passkey corresponds to the hashed passkey
func VerifyBase32Passkey(base32Passkey string, hashedPasskey []byte) (bool, error) {
	// Decode base32 passkey back into the 6-byte combined parts
	combinedParts, err := DecodeBase32(base32Passkey)
	if err != nil {
		return false, fmt.Errorf("failed to decode base32 passkey: %v", err)
	}

	// Generate root hash using the combined parts and hashed passkey
	rootHash, err := GenerateRootHash(combinedParts, hashedPasskey)
	if err != nil {
		return false, err
	}

	// Now, compare the root hash with the hashed passkey (which was generated during key creation)
	// You can directly compare rootHash and hashedPasskey or return the fingerprint for verification

	// For example, if you store the fingerprint generated during key creation,
	// you can directly compare it with rootHash to verify correctness:
	return bytes.Equal(rootHash, hashedPasskey), nil
}
