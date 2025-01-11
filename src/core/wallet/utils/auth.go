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
	"encoding/hex"
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

// isHex checks if a string is a valid hexadecimal representation.
// Parameters:
// - s: The input string to validate.
// Returns:
// - true if the string is valid hexadecimal, false otherwise.
func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
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
	combined := append(append([]byte(passphrase), combinedParts...), hashedPasskey...)

	// Generate the fingerprint (HMAC) using the combined data and passphrase as the key.
	fingerprint, err := GenerateHMAC(combined, []byte(passphrase))
	if err != nil {
		return nil, fmt.Errorf("failed to generate chain code: %v", err)
	}

	return fingerprint, nil
}

// VerifyLogin authenticates a user by comparing a generated fingerprint with a stored one.
// Parameters:
// - Base32Passkey: A base32-encoded string representing the user's passkey (expected in hexadecimal format).
// - passphrase: The secret passphrase used for generating the fingerprint.
// - storedFingerprint: The previously stored fingerprint to compare against.
// - combinedParts: Additional data used during fingerprint generation.
// Returns:
// - true if authentication is successful, false otherwise.
// - An error if the process encounters issues.
func VerifyLogin(Base32Passkey, passphrase string, storedFingerprint []byte, combinedParts []byte) (bool, error) {
	// Validate that the input Base32Passkey is a valid hexadecimal string.
	if !isHex(Base32Passkey) {
		return false, fmt.Errorf("invalid hexadecimal input")
	}

	// Generate a fingerprint using the passphrase and combined parts.
	generatedFingerprint, err := GenerateChainCode(passphrase, combinedParts, []byte(Base32Passkey))
	if err != nil {
		return false, fmt.Errorf("failed to generate chain code: %v", err)
	}

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

	return true, nil // Fingerprints match; authentication is successful.
}
