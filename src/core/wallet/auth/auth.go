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

package auth

import (
	"crypto/hmac"
	"encoding/base32"
	"fmt"
	"sync"

	"golang.org/x/crypto/sha3"
)

// Mutex to protect access to the stored fingerprints
var mu sync.Mutex

// Map to store generated fingerprints (HMAC) directly by the Base32 encoded fingerprint string
var storedFingerprints = make(map[string][]byte)

// EncodeBase32 encodes a byte slice into a Base32 string without padding
func EncodeBase32(data []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
}

// DecodeBase32 decodes a Base32 string into a byte slice
func DecodeBase32(base32Str string) ([]byte, error) {
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(base32Str)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base32 string: %v", err)
	}
	return decoded, nil
}

// GenerateHMAC generates a keyed-hash message authentication code (HMAC) using SHA3-512 (Keccak-512).
func GenerateHMAC(data []byte, key []byte) ([]byte, error) {
	h := hmac.New(sha3.NewLegacyKeccak512, key)
	if _, err := h.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write data to HMAC: %v", err)
	}
	return h.Sum(nil), nil
}

// GenerateChainCode generates a fingerprint (HMAC) by applying HMAC-SHA3-512 on the combined input data (passphrase + Base32 passkey).
func GenerateChainCode(passphrase string, combinedParts []byte) ([]byte, error) {
	// Combine the passphrase and combinedParts (Base32 passkey) into a single byte slice.
	KeyMaterial := append([]byte(passphrase), combinedParts...)

	// Debugging: Print the KeyMaterial for both passphrase and Base32 passkey
	fmt.Printf("KeyMaterial: %x\n", KeyMaterial)

	// Generate the fingerprint (HMAC) using the combined data (passphrase + Base32 passkey) and passphrase as the key.
	fingerprint, err := GenerateHMAC(KeyMaterial, []byte(passphrase))
	if err != nil {
		return nil, fmt.Errorf("failed to generate fingerprint: %v", err)
	}

	// Store the generated fingerprint in memory directly as raw bytes
	mu.Lock() // Locking to ensure safe access to the stored fingerprints

	// Use passphrase + combinedParts as the key to store the fingerprint
	key := string(append([]byte(passphrase), combinedParts...))
	storedFingerprints[key] = fingerprint

	// Debugging: Print the key used to store the fingerprint
	fmt.Printf("Stored Key: %s\n", key)
	fmt.Printf("Stored Fingerprint: %x\n", fingerprint)

	mu.Unlock()

	// Return the generated fingerprint.
	return fingerprint, nil
}

// VerifyFingerPrint authenticates a user by comparing a generated fingerprint with a stored one.
func VerifyFingerPrint(Base32Passkey, passphrase string) (bool, error) {
	mu.Lock() // Lock memory access for thread-safety
	defer mu.Unlock()

	// Decode the Base32 passkey to get its byte representation.
	decodedPasskey, err := DecodeBase32(Base32Passkey)
	if err != nil {
		return false, fmt.Errorf("failed to decode passkey: %v", err)
	}

	// Combine the decoded passkey and passphrase into a single byte slice
	combined := append(decodedPasskey, []byte(passphrase)...)

	// Generate the fingerprint using the combined data (passkey + passphrase).
	generatedFingerprint, err := GenerateHMAC(combined, []byte(passphrase))
	if err != nil {
		return false, fmt.Errorf("failed to generate fingerprint: %v", err)
	}

	// Retrieve the stored fingerprint from the map using the Base32 encoded passkey
	storedFingerprint, exists := storedFingerprints[Base32Passkey]
	if !exists {
		// If no stored fingerprint exists for the passphrase and Base32 passkey combination, authentication fails
		return false, fmt.Errorf("no stored fingerprint for the given passphrase and Base32 passkey combination")
	}

	// Debugging statement to ensure the comparison is correct
	fmt.Printf("Stored Fingerprint: %x\n", storedFingerprint)

	// Compare the generated fingerprint with the stored fingerprint.
	if string(storedFingerprint) == string(generatedFingerprint) {
		// If they match, authentication is successful
		return true, nil
	}

	// Debugging statement if the fingerprints don't match
	fmt.Println("Fingerprint did not match!")
	return false, nil // Fingerprints don't match; authentication failed.
}
