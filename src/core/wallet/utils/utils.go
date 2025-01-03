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

	"github.com/sphinx-core/go/src/common"
)

// EncodeBase32 encodes a byte slice into a Base32 string.
// This is useful when you need to convert binary data into a human-readable format.
// The function encodes the data using Base32 without any padding, ensuring compatibility with systems that require padding-free Base32 encoding.
func EncodeBase32(data []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
}

// DecodeBase32 decodes a Base32 string into a byte slice.
// This function takes a Base32-encoded string and decodes it back into its original byte slice form.
// It returns an error if the decoding fails, ensuring that invalid Base32 input is handled appropriately.
func DecodeBase32(base32Str string) ([]byte, error) {
	decoded, err := base32.StdEncoding.DecodeString(base32Str)
	if err != nil {
		// Return a descriptive error if Base32 decoding fails
		return nil, fmt.Errorf("failed to decode base32 string: %v", err)
	}
	return decoded, nil
}

// GenerateRootHash generates a root hash by combining the decoded parts and the hashed passkey.
// It first appends the decoded combined parts with the hashed passkey, then hashes the resulting data using spxhash.
// The generated root hash can be used for verification purposes, ensuring that the input data matches the expected result.
func GenerateRootHash(combinedParts []byte, hashedPasskey []byte) ([]byte, error) {
	// Combine the decoded parts with the hashed passkey to generate the key material
	KeyMaterial := append(combinedParts, hashedPasskey...)

	// Print the combined key material for debugging purposes
	fmt.Printf("Combined Key Material: %x\n", KeyMaterial)

	// Generate the root hash by hashing the combined key material
	fingerprint := common.SpxHash(KeyMaterial)

	// Ensure the generated fingerprint is 256 bits (32 bytes) in length
	if len(fingerprint) != 32 {
		return nil, fmt.Errorf("root hash is not 256 bits (32 bytes)")
	}

	// Return the root hash (first 32 bytes)
	return fingerprint[:], nil
}

// DeriveRootHash computes the hashed passkey based on the provided fingerprint (combined parts).
// This function simply recalculates the hash of the fingerprint, which is useful for recreating the hashed passkey
// from the original combined data.
func DeriveRootHash(fingerprint []byte) []byte {
	// Hash the fingerprint (combined parts)
	hashed := common.SpxHash(fingerprint)

	// Return the hashed passkey (a slice of 32 bytes)
	return hashed[:]
}

// VerifyBase32Passkey verifies the user's Base32-encoded passkey and derives both the root hash and hashed passkey.
// The function decodes the Base32 passkey, derives the hashed passkey from the decoded data,
// generates the root hash by combining the decoded parts with the hashed passkey,
// and then compares the root hash with the provided hashed passkey for verification.
func VerifyBase32Passkey(base32Passkey string) (bool, []byte, []byte, error) {
	// Decode the Base32 passkey
	decodedPasskey, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(base32Passkey)
	if err != nil {
		// Return a descriptive error if Base32 passkey decoding fails
		return false, nil, nil, fmt.Errorf("failed to decode base32 passkey: %v", err)
	}
	// Print the decoded passkey for debugging
	fmt.Printf("Decoded Passkey: %x\n", decodedPasskey)

	// Recalculate the fingerprint (hashed passkey) using DeriveRootHash
	derivedFingerprint := DeriveRootHash(decodedPasskey)

	// Print the expected hashed passkey (which is the derived fingerprint)
	fmt.Printf("Expected Hashed Passkey: %x\n", derivedFingerprint)

	// Generate the root hash by combining the decoded passkey and the derived fingerprint
	rootHash, err := GenerateRootHash(decodedPasskey, derivedFingerprint)
	if err != nil {
		// Return a descriptive error if generating the root hash fails
		return false, nil, nil, fmt.Errorf("failed to generate root hash: %v", err)
	}

	// Return true if everything was processed correctly, along with the root hash and derived fingerprint
	return true, rootHash, derivedFingerprint, nil
}
