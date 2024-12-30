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
// This is useful when you need to convert binary data into a human-readable format.
func EncodeBase32(data []byte) string {
	return base32.StdEncoding.EncodeToString(data)
}

// DecodeBase32 decodes a Base32 string into a byte slice.
// This function takes a Base32-encoded string and decodes it back into its original byte slice form.
// It returns an error if the decoding fails.
func DecodeBase32(base32Str string) ([]byte, error) {
	decoded, err := base32.StdEncoding.DecodeString(base32Str)
	if err != nil {
		// If there's an error in decoding, return the error with a descriptive message
		return nil, fmt.Errorf("failed to decode base32 string: %v", err)
	}
	return decoded, nil
}

// GenerateRootHash combines the decoded combined parts and the hashed passkey for verification.
// This function appends the combined parts with the hashed passkey and then hashes the resulting data using SHA-256.
// The root hash can then be used for verification purposes.
// GenerateRootHash combines the decoded combined parts and the hashed passkey for verification.
// This function appends the combined parts with the hashed passkey and then hashes the resulting data using SHA-256.
// The root hash can then be used for verification purposes.
func GenerateRootHash(combinedParts []byte, hashedPasskey []byte) ([]byte, error) {
	// Combine the decoded parts with the hashed passkey
	combined := append(combinedParts, hashedPasskey...)
	// Generate the root hash by applying SHA-256 on the combined data
	rootHash := sha256.Sum256(combined)
	// Ensure the length is 32 bytes (256 bits)
	if len(rootHash) != 32 {
		return nil, fmt.Errorf("root hash is not 256 bits (32 bytes)")
	}
	// Return the root hash (256 bits = 32 bytes)
	return rootHash[:], nil
}

// DeriveHashedPasskey computes the hashed passkey based on the provided combined parts.
// This function simply takes the combined parts and hashes them using SHA-256.
// This is useful to recreate the hashed passkey from the original data.
func DeriveBase32Passkey(combinedParts []byte) []byte {
	// Hash the combined parts using SHA-256
	hashed := sha256.Sum256(combinedParts)
	// Return the hashed passkey as a slice of bytes
	return hashed[:]
}

// VerifyBase32Passkey verifies the user's Base32-encoded passkey and derives both the root hash and hashed passkey.
// This function takes the user's Base32-encoded passkey, decodes it, derives the hashed passkey from the decoded data,
// and generates a root hash by combining the decoded parts and hashed passkey.
// Finally, it compares the root hash with the provided hashed passkey to verify correctness.
// If the verification passes, it returns true, along with the root hash and the derived hashed passkey.
func VerifyBase32Passkey(base32Passkey string) (bool, []byte, []byte, error) {
	// Decode the Base32-encoded passkey to obtain the original combined parts
	combinedParts, err := DecodeBase32(base32Passkey)
	if err != nil {
		// Return an error if decoding the passkey fails
		return false, nil, nil, fmt.Errorf("failed to decode base32 passkey: %v", err)
	}

	// Derive the hashed passkey by hashing the decoded combined parts
	hashedPasskey := DeriveBase32Passkey(combinedParts)

	// Generate the root hash using the combined parts and the derived hashed passkey
	rootHash, err := GenerateRootHash(combinedParts, hashedPasskey)
	if err != nil {
		// Return an error if generating the root hash fails
		return false, nil, nil, err
	}

	// For this example, assume the stored root hash matches the derived one (mock verification)
	// Replace this with actual comparison logic to verify the root hash against a stored value
	// The root hash is compared to the hashed passkey to verify if they match
	isVerified := bytes.Equal(rootHash, hashedPasskey)

	// Return the result of the verification, along with the root hash and hashed passkey
	return isVerified, rootHash, hashedPasskey, nil
}
