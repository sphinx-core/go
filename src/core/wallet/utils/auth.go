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
// The function takes two arguments: 'data' (the message) and 'key' (the secret key used to create the HMAC).
func GenerateHMAC(data []byte, key []byte) ([]byte, error) {
	// Create a new HMAC object using the SHA3-512 (Keccak-512) hash function and the provided key.
	// 'hmac.New' initializes a new HMAC using a cryptographic hash function and the provided key.
	h := hmac.New(sha3.NewLegacyKeccak512, key)

	// Write the data (message) to the HMAC object to process it.
	// 'h.Write' processes the input data to generate the hash.
	_, err := h.Write(data)
	if err != nil {
		// If there was an error while writing data to the HMAC object, return nil and an error message.
		return nil, fmt.Errorf("failed to write data to HMAC: %v", err)
	}

	// Finalize the HMAC computation and return the resulting hash (message authentication code).
	// 'h.Sum(nil)' completes the HMAC computation and returns the hash as a byte slice.
	return h.Sum(nil), nil
}

// Helper function to check if a string is valid hexadecimal.
// This function verifies whether the input string 's' is a valid hexadecimal representation.
func isHex(s string) bool {
	// Try to decode the string 's' into a byte slice using the 'hex.DecodeString' function.
	// If decoding succeeds, it means the string is a valid hexadecimal string.
	_, err := hex.DecodeString(s)
	return err == nil // Return 'true' if there was no error, indicating valid hexadecimal; otherwise, return 'false'.
}

// GenerateChainCode generates a chain code by applying HMAC on the passphrase and combinedParts.
// It returns the final result as a hash.
func GenerateHmacKey(passphrase string, combinedParts []byte) ([]byte, error) {
	// Combine the passphrase and the combined parts into a single byte slice.
	// This creates the input data for HMAC generation.
	combined := append([]byte(passphrase), combinedParts...)

	// Generate the chain code using HMAC by calling 'GenerateHMAC' with the combined data and passphrase as the key.
	// The function 'GenerateHMAC' will return a hashed value based on the input data and passphrase.
	hmackey, err := GenerateHMAC(combined, []byte(passphrase))
	if err != nil {
		// If there was an error generating the HMAC, return nil and an error message.
		return nil, fmt.Errorf("failed to generate chain code: %v", err)
	}

	// Return the raw hash (HMAC result) without any encoding, as the key used to generate the chain code.
	return hmackey, nil
}

// VerifyLogin verifies the user's login credentials by generating a chain code using the passkey and passphrase.
// It then compares this generated chain code with the stored one to authenticate the user.
func VerifyLogin(Base32Passkey, passphrase string, storedHmacKey []byte, combinedParts []byte) (bool, error) {
	// Step 1: Check if the user input is a valid hexadecimal string.
	// 'Base32Passkey' is expected to be a valid hexadecimal string; if not, return an error.
	if !isHex(Base32Passkey) {
		return false, fmt.Errorf("invalid hexadecimal input") // If the input is not valid hex, return false and an error.
	}

	// Step 2: Generate the chain code using the passphrase and combined parts (passed as arguments).
	// 'GenerateHmacKey' creates an HMAC using the passphrase and combined parts, resulting in a chain code.
	hmackey, err := GenerateHmacKey(passphrase, combinedParts)
	if err != nil {
		// If there was an error generating the chain code, return false and the error message.
		return false, fmt.Errorf("failed to generate chain code: %v", err)
	}

	// Step 3: Compare the generated chain code with the stored chain code to verify the login.
	// First, check if the length of the generated HMAC matches the length of the stored HMAC.
	if len(hmackey) != len(storedHmacKey) {
		// If the lengths do not match, the hashes are definitely different, so return false.
		return false, nil
	}

	// Loop through each byte of the generated HMAC and stored HMAC to check if they are identical.
	// This step ensures that the actual content of the hashes match byte by byte.
	for i := range hmackey {
		if hmackey[i] != storedHmacKey[i] {
			// If any byte does not match, the hashes don't match, so return false.
			return false, nil
		}
	}

	// If all bytes match, return true indicating the login is successful.
	return true, nil // The hashes match, meaning the login is successful.
}
