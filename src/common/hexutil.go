// MIT License
//
// # Copyright (c) 2024 sphinx-core
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

package common

import (
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/sha3"
)

// Address manipulates a given contract address by adding or removing the "0x" prefix.
// If the input starts with "0x", it removes the prefix; otherwise, it adds "0x".
func Address(hash []byte) (string, error) {
	if len(hash) != 32 {
		return "", fmt.Errorf("invalid hash length: expected 32 bytes, got %d", len(hash))
	}

	// Convert the hash to a hexadecimal string
	hexAddress := hex.EncodeToString(hash)

	// Take the last 20 bytes (40 hex characters)
	trimmedHexAddress := hexAddress[len(hexAddress)-40:]

	// Compute the checksum using the SHAKE256 function
	checksumAddress := applyChecksum(trimmedHexAddress)

	// Add the "0x" prefix if it doesn't exist; otherwise, remove it
	if strings.HasPrefix(checksumAddress, "0x") {
		// Remove the "0x" prefix
		return checksumAddress[2:], nil
	}

	// Add the "0x" prefix
	return fmt.Sprintf("0x%s", checksumAddress), nil
}

// applyChecksum applies a checksum to a given address string using SHAKE256.
func applyChecksum(address string) string {
	// Convert the address to lowercase
	lowerAddress := strings.ToLower(address)

	// Compute the SHAKE256 hash of the lowercase address
	hasher := sha3.NewShake256()
	hasher.Write([]byte(lowerAddress))

	// Get 32 bytes (64 hex characters) of output from SHAKE256
	hash := make([]byte, 32)
	hasher.Read(hash)
	hashHex := hex.EncodeToString(hash)

	// Apply checksum: uppercase if corresponding hash hex character is >= 8
	var checksumAddress strings.Builder
	for i, char := range lowerAddress {
		if char >= '0' && char <= '9' {
			checksumAddress.WriteRune(char) // Keep numbers as-is
		} else {
			if hashHex[i] >= '8' {
				checksumAddress.WriteRune(rune(char - 32)) // Convert to uppercase
			} else {
				checksumAddress.WriteRune(char) // Keep lowercase
			}
		}
	}

	return checksumAddress.String()
}

// ValidateAddress checks if an address is valid and matches the SHAKE256-based checksum.
func ValidateAddress(address string) (bool, error) {
	// Ensure the address starts with "0x"
	if !strings.HasPrefix(address, "0x") {
		return false, fmt.Errorf("address must start with '0x'")
	}

	// Remove "0x" prefix for validation
	trimmedAddress := address[2:]

	// Check the length
	if len(trimmedAddress) != 40 {
		return false, fmt.Errorf("invalid address length: expected 40 characters, got %d", len(trimmedAddress))
	}

	// Compare the checksum
	expected := applyChecksum(trimmedAddress)
	if trimmedAddress != expected {
		return false, fmt.Errorf("checksum mismatch: expected %s, got %s", expected, trimmedAddress)
	}

	return true, nil
}
