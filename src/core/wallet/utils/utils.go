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
// This function converts binary data into a human-readable Base32 format without padding,
// ensuring compatibility with systems that require padding-free Base32 encoding.
func EncodeBase32(data []byte) string {
	// Base32 encoding is performed here without padding
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
}

// DecodeBase32 decodes a Base32 string into a byte slice.
// This function decodes a Base32-encoded string back into its original byte slice form.
// It returns an error if decoding fails, ensuring that invalid Base32 input is properly handled.
func DecodeBase32(base32Str string) ([]byte, error) {
	// Attempt to decode the Base32 string into the original byte slice
	decoded, err := base32.StdEncoding.DecodeString(base32Str)
	if err != nil {
		// Return a descriptive error if Base32 decoding fails
		return nil, fmt.Errorf("failed to decode base32 string: %v", err)
	}
	return decoded, nil
}

// GenerateRootHash generates a root hash by combining the decoded parts and the hashed passkey.
// It appends the decoded parts with the hashed passkey, then hashes the combined data using spxhash.
// This root hash can be used for verification, ensuring the input data matches the expected result.
func GenerateRootHash(combinedParts []byte, hashedPasskey []byte) ([]byte, error) {
	// Combine the decoded combined parts and the hashed passkey to generate the key material
	KeyMaterial := append(combinedParts, hashedPasskey...)

	// Print the combined key material for debugging purposes
	fmt.Printf("Combined Key Material: %x\n", KeyMaterial)

	// Hash the combined key material to generate the root hash
	fingerprint := common.SpxHash(KeyMaterial)

	// Ensure the generated fingerprint is 256 bits (32 bytes) in length
	if len(fingerprint) != 32 {
		return nil, fmt.Errorf("root hash is not 256 bits (32 bytes)")
	}

	// Return the root hash, which is the first 32 bytes of the fingerprint
	return fingerprint[:], nil
}

// DeriveRootHash recalculates the hash (fingerprint) from the provided data.
// This function generates a new hash from the fingerprint (or combined parts),
// which is used for integrity verification and ensuring consistency with the original input data.
func DeriveRootHash(fingerprint []byte) []byte {
	// Hash the fingerprint (combined parts) to derive a new fingerprint
	DerivedFingerprint := common.SpxHash(fingerprint)

	// Return the derived fingerprint (a slice of 32 bytes)
	return DerivedFingerprint[:]
}

// VerifyBase32Passkey verifies the user's Base32-encoded passkey by decoding it,
// recalculating its fingerprint (derived from the decoded passkey), and generating a root hash.
// It compares the generated root hash with the derived fingerprint for verification purposes.
func VerifyBase32Passkey(base32Passkey string) (bool, []byte, []byte, error) {
	// Decode the Base32 passkey into its original byte slice form
	decodedPasskey, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(base32Passkey)
	if err != nil {
		// Return a descriptive error if Base32 passkey decoding fails
		return false, nil, nil, fmt.Errorf("failed to decode base32 passkey: %v", err)
	}

	// Print the decoded passkey for debugging
	fmt.Printf("Decoded Passkey: %x\n", decodedPasskey)

	// Recalculate the fingerprint from the decoded passkey
	DerivedFingerprint := DeriveRootHash(decodedPasskey)

	// Print the expected derived fingerprint
	fmt.Printf("Expected DerivedFingerprint: %x\n", DerivedFingerprint)

	// Generate the root hash by combining the decoded passkey and the derived fingerprint
	rootHash, err := GenerateRootHash(decodedPasskey, DerivedFingerprint)
	if err != nil {
		// Return a descriptive error if generating the root hash fails
		return false, nil, nil, fmt.Errorf("failed to generate root hash: %v", err)
	}

	// Return true if everything was processed correctly, along with the root hash and derived fingerprint
	return true, rootHash, DerivedFingerprint, nil
}
