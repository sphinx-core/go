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
	"fmt"

	"golang.org/x/crypto/sha3"
)

// GenerateHMAC generates a keyed-hash message authentication code (HMAC) using SHA3-512 (Keccak-512).
// Parameters:
// - data: The message to be hashed.
// - key: The secret key used to generate the HMAC.
// Returns:
// - The generated HMAC as a byte slice.
// - An error if the process fails.
func GenerateHMAC(data []byte, key []byte) ([]byte, error) {
	// Initialize a new HMAC object using SHA3-512 (Keccak-512) and the provided key.
	h := hmac.New(sha3.NewLegacyKeccak512, key)

	// Write the message data to the HMAC object.
	if _, err := h.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write data to HMAC: %v", err)
	}

	// Compute and return the HMAC.
	return h.Sum(nil), nil
}

// DecodeBase32 decodes a Base32-encoded string into its byte representation.
// Parameters:
// - s: The input Base32-encoded string.
// Returns:
// - The decoded byte slice, or an error if decoding fails.
func DecodeBase32(s string) ([]byte, error) {
	decoded, err := base32.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Base32 passkey: %v", err)
	}
	return decoded, nil
}

// GenerateChainCode generates a fingerprint (HMAC) by applying HMAC-SHA3-512 on the combined input data.
// Parameters:
// - passphrase: The secret passphrase used as the HMAC key.
// - combinedParts: Additional data to be hashed.
// - hashedPasskey: A hashed version of the user's passkey.
// Returns:
// - The generated fingerprint (HMAC) as a byte slice.
// - An error if the process fails.
func GenerateChainCode(passphrase string, combinedParts, hashedPasskey []byte) ([]byte, error) {
	// Combine the passphrase, combined parts, and hashed passkey into a single byte slice.
	KeyMaterial := append(append([]byte(passphrase), combinedParts...), hashedPasskey...)

	// Generate the fingerprint (HMAC) using the combined data and passphrase as the key.
	fingerprint, err := GenerateHMAC(KeyMaterial, []byte(passphrase))
	if err != nil {
		return nil, fmt.Errorf("failed to generate fingerprint: %v", err)
	}

	// Return only the fingerprint.
	return fingerprint, nil
}

// VerifyFingerPrint authenticates a user by comparing a generated fingerprint with a stored one.
// Parameters:
// - Base32Passkey: A Base32-encoded string representing the user's passkey.
// - passphrase: The secret passphrase used for generating the fingerprint.
// - storedFingerprint: The previously stored fingerprint to compare against.
// Returns:
// - true if authentication is successful, false otherwise.
// - An error if the process encounters issues.
func VerifyFingerPrint(Base32Passkey, passphrase string, storedFingerprint []byte) (bool, error) {
	// Decode the Base32 passkey to get its byte representation.
	decodedPasskey, err := DecodeBase32(Base32Passkey)
	if err != nil {
		return false, fmt.Errorf("failed to decode passkey: %v", err)
	}

	// Generate the fingerprint using the decoded passkey and passphrase.
	generatedFingerprint, err := GenerateHMAC(decodedPasskey, []byte(passphrase))
	if err != nil {
		return false, fmt.Errorf("failed to generate fingerprint: %v", err)
	}

	// Print the generated fingerprint (in hex) regardless of whether it's a match
	fmt.Printf("Generated Fingerprint: %x\n", generatedFingerprint)

	// Compare the generated fingerprint with the stored fingerprint.
	if len(generatedFingerprint) != len(storedFingerprint) {
		return false, nil // Length mismatch indicates a failed comparison.
	}

	// Perform a byte-by-byte comparison to verify fingerprints.
	for i := range generatedFingerprint {
		if generatedFingerprint[i] != storedFingerprint[i] {
			return false, nil
		}
	}

	// Print success message when the fingerprints match
	fmt.Println("Fingerprint matched successfully!")

	return true, nil // Fingerprints match; authentication is successful.
}
