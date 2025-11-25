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

// go/src/common/hexutil.go
package common

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
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

// Bytes2Hex converts bytes to hexadecimal string
func Bytes2Hex(b []byte) string {
	return hex.EncodeToString(b)
}

// Hex2Bytes converts hexadecimal string to bytes
func Hex2Bytes(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

// FormatNonce formats a uint64 nonce as a 16-character hex string (Ethereum compatible)
func FormatNonce(nonce uint64) string {
	return fmt.Sprintf("%016x", nonce)
}

// FormatNonce32 formats a nonce as a 32-character hex string (64-bit)
func FormatNonce32(nonce uint64) string {
	return fmt.Sprintf("%032x", nonce)
}

// ParseNonce converts a hex nonce string back to uint64
func ParseNonce(nonceStr string) (uint64, error) {
	return strconv.ParseUint(nonceStr, 16, 64)
}

// GenerateRandomNonce generates a cryptographically secure random nonce
func GenerateRandomNonce() string {
	// Generate 8 random bytes (64 bits) for nonce
	randomBytes := make([]byte, 8)
	_, err := rand.Read(randomBytes)
	if err != nil {
		// Fallback to timestamp-based randomness if crypto rand fails
		fallbackNonce := GetCurrentTimestamp()
		randomBytes = make([]byte, 8)
		binary.BigEndian.PutUint64(randomBytes, uint64(fallbackNonce))
	}

	// Convert to 16-character hex string (like Ethereum)
	return FormatNonce(binary.BigEndian.Uint64(randomBytes))
}

// GenerateRandomNonceUint64 generates a random uint64 nonce
func GenerateRandomNonceUint64() uint64 {
	var nonce uint64
	binary.Read(rand.Reader, binary.BigEndian, &nonce)
	return nonce
}

// ValidateNonceFormat validates if a nonce string is properly formatted
func ValidateNonceFormat(nonce string) error {
	if len(nonce) != 16 {
		return fmt.Errorf("nonce must be 16 characters long, got %d", len(nonce))
	}

	// Check if it's valid hex
	_, err := hex.DecodeString(nonce)
	if err != nil {
		return fmt.Errorf("nonce must be valid hex: %w", err)
	}

	return nil
}

// FormatHash formats a byte slice as a 64-character hex hash string
func FormatHash(hash []byte) string {
	return fmt.Sprintf("%064x", hash)
}

// FormatAddress formats an address as a 40-character hex string
func FormatAddress(address []byte) string {
	return fmt.Sprintf("%040x", address)
}

// FormatBigInt formats a big.Int as a hex string with optional padding
func FormatBigInt(value *big.Int, padToLength int) string {
	hexStr := fmt.Sprintf("%x", value)
	if padToLength > 0 && len(hexStr) < padToLength {
		// Pad with leading zeros
		return strings.Repeat("0", padToLength-len(hexStr)) + hexStr
	}
	return hexStr
}

// ParseBigInt parses a hex string into a big.Int
func ParseBigInt(hexStr string) (*big.Int, error) {
	value := new(big.Int)
	_, success := value.SetString(hexStr, 16)
	if !success {
		return nil, fmt.Errorf("invalid hex string: %s", hexStr)
	}
	return value, nil
}

// BytesToHexWithPrefix converts bytes to hex with "0x" prefix
func BytesToHexWithPrefix(b []byte) string {
	return "0x" + hex.EncodeToString(b)
}

// HexToBytesWithoutPrefix converts hex string (with or without prefix) to bytes
func HexToBytesWithoutPrefix(hexStr string) ([]byte, error) {
	// Remove "0x" prefix if present
	cleanHex := strings.TrimPrefix(hexStr, "0x")
	return hex.DecodeString(cleanHex)
}

// IsValidHexString checks if a string is valid hexadecimal
func IsValidHexString(s string) bool {
	if len(s)%2 != 0 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// ZeroNonce returns the zero nonce (all zeros)
func ZeroNonce() string {
	return "0000000000000000"
}

// MaxNonce returns the maximum possible nonce value
func MaxNonce() string {
	return "ffffffffffffffff"
}

// NonceToBytes converts a nonce string to bytes
func NonceToBytes(nonce string) ([]byte, error) {
	if err := ValidateNonceFormat(nonce); err != nil {
		return nil, err
	}
	return hex.DecodeString(nonce)
}

// BytesToNonce converts bytes to a nonce string
func BytesToNonce(b []byte) (string, error) {
	if len(b) != 8 {
		return "", fmt.Errorf("nonce bytes must be 8 bytes long, got %d", len(b))
	}
	nonceUint := binary.BigEndian.Uint64(b)
	return FormatNonce(nonceUint), nil
}
