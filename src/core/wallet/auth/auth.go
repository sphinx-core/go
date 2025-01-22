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
	"bytes"
	"crypto/hmac"
	"encoding/base32"
	"fmt"
	"sync"

	"golang.org/x/crypto/sha3"
)

// This package imnplementation of SIPS0004 & SIPS0005
// https://github.com/sphinx-core/sips/wiki/SIPS0004
// https://github.com/sphinx-core/sips/wiki/SIPS0005

// Mutex to protect access to the stored fingerprints
var mu sync.Mutex

// Map to store generated fingerprints (HMAC) directly by the combined key
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

// memoryCleanse overwrites a byte slice with zeroes to securely erase sensitive data
func memoryCleanse(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}

// GenerateHMAC generates a keyed-hash message authentication code (HMAC) using SHA3-512.
func GenerateHMAC(data []byte, key []byte) ([]byte, error) {
	h := hmac.New(sha3.New512, key)
	if _, err := h.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write data to HMAC: %v", err)
	}
	return h.Sum(nil), nil
}

// GenerateChainCode generates a fingerprint (HMAC) by applying HMAC-SHA3-512 on the combined input data (passphrase + Base32 passkey).
func GenerateChainCode(passphrase string, combinedParts []byte) ([]byte, error) {
	// Combine the passphrase and combinedParts (Base32 passkey) into a single byte slice.
	KeyMaterial := append([]byte(passphrase), combinedParts...)

	// Generate the fingerprint (HMAC) using the combined data (passphrase + Base32 passkey) and passphrase as the key.
	fingerprint, err := GenerateHMAC(KeyMaterial, []byte(passphrase))
	if err != nil {
		return nil, fmt.Errorf("failed to generate fingerprint: %v", err)
	}

	// Store the generated fingerprint in memory directly as raw bytes
	mu.Lock() // Locking to ensure safe access to the stored fingerprints

	// Combine passphrase and combinedParts as the single key for storing the fingerprint
	key := string(append([]byte(passphrase), combinedParts...))
	storedFingerprints[key] = fingerprint

	mu.Unlock()

	// Securely cleanse the sensitive data
	memoryCleanse(KeyMaterial)
	memoryCleanse([]byte(passphrase)) // Securely cleanse passphrase

	// Return the generated fingerprint.
	return fingerprint, nil
}

// VerifyFingerPrint authenticates a user by comparing a generated fingerprint with a stored one.
func VerifyFingerPrint(Base32Passkey, passphrase string) (bool, error) {
	// Decode the Base32 passkey into its original byte slice
	decodedPasskey, err := DecodeBase32(Base32Passkey)
	if err != nil {
		return false, fmt.Errorf("failed to decode Base32 passkey: %v", err)
	}

	// Combine the passphrase and the decoded passkey into a single byte slice for verification
	KeyMaterial := append([]byte(passphrase), decodedPasskey...)

	// Generate the fingerprint using the same method as in GenerateChainCode
	generatedFingerprint, err := GenerateHMAC(KeyMaterial, []byte(passphrase))
	if err != nil {
		return false, fmt.Errorf("failed to generate fingerprint for verification: %v", err)
	}

	// Retrieve the stored fingerprint from memory
	mu.Lock()                                                            // Lock access to storedFingerprints for thread safety
	storedFingerprint, exists := storedFingerprints[string(KeyMaterial)] // Directly use m[string(key)]
	mu.Unlock()

	if !exists {
		// If the fingerprint is not found in memory, verification fails
		return false, fmt.Errorf("no stored fingerprint found for the provided passphrase and Base32 passkey")
	}

	// Print the found fingerprint value for debugging
	fmt.Printf("Found Fingerprint: %x\n", storedFingerprint)

	// Compare the generated fingerprint with the stored fingerprint
	if !bytes.Equal(generatedFingerprint, storedFingerprint) {
		// If they do not match, verification fails
		return false, fmt.Errorf("fingerprint mismatch")
	}

	// Securely cleanse the sensitive data after use
	memoryCleanse(KeyMaterial)
	memoryCleanse([]byte(passphrase)) // Securely cleanse passphrase

	// If everything matches, verification succeeds
	return true, nil
}
