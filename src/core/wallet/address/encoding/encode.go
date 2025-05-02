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

package encode

import (
	"crypto/sha256"
	"crypto/sha512"
	"errors"

	"github.com/btcsuite/btcutil/base58"
	"github.com/sphinx-core/go/src/common"
)

// Prefix byte for internal processing (used only for checksum validation)
const prefixByte = 0x78 // ASCII 'x'

// Error definitions
var (
	ErrChecksum      = errors.New("checksum error")                                        // Error for invalid checksum
	ErrInvalidFormat = errors.New("invalid format: version and/or checksum bytes missing") // Error for missing version or checksum bytes
)

// pubKeyToHash hashes the public key twice using the SphinxHash algorithm
// First hash the public key using SpxHash, then hash the result again to generate the final hash
func pubKeyToHash(pubKey []byte) []byte {
	// Apply the SphinxHash algorithm twice to the public key
	h1 := common.SpxHash(pubKey)
	h2 := common.SpxHash(h1)
	return h2 // Return the second hash as the result
}

// spxToSha applies SHA-512/224 hashing to the SphinxHash result
// This is used to create a shorter, fixed-length hash from the public key hash
func spxToSha(hashPubKey []byte) []byte {
	// Initialize the SHA-512/224 hasher
	sha512_224Hash := sha512.New512_224()

	// Write the input data (public key hash) to the hasher
	sha512_224Hash.Write(hashPubKey)

	// Return the resulting hash as a byte slice
	return sha512_224Hash.Sum(nil)
}

// Checksum calculates the checksum by hashing the input twice with SHA-256
// The checksum is the first 4 bytes of the second SHA-256 hash
func Checksum(data []byte) []byte {
	// First hash the input data with SHA-256
	firstHash := sha256.Sum256(data)

	// Hash the result again to get a more secure checksum
	secondHash := sha256.Sum256(firstHash[:])

	// Return the first 4 bytes of the second hash as the checksum
	return secondHash[:4]
}

// shaToBase58Check encodes the hash with Base58 and prepends the "x" manually
// This function applies a checksum to the data before encoding it in Base58
func shaToBase58Check(shaPubKey []byte) string {
	// Prepare data for checksum validation by adding the prefix byte
	prefixedData := append([]byte{prefixByte}, shaPubKey...)

	// Calculate checksum for the prefixed data
	checksum := Checksum(prefixedData)

	// Combine the hash and checksum (exclude prefix byte for encoding)
	data := append(shaPubKey, checksum...)

	// Encode the combined data in Base58 format
	encoded := base58.Encode(data)

	// Prepend "x" to the encoded string for consistency with the prefix
	return "x" + encoded
}

// GenerateAddress generates an address from a public key
// This function hashes the public key and applies the necessary encoding to generate a valid address
func GenerateAddress(pubKey []byte) string {
	// Hash the public key twice using the SphinxHash algorithm
	hashedPubKey := pubKeyToHash(pubKey)

	// Apply SHA-512/224 hashing to the result
	shaPubKey := spxToSha(hashedPubKey)

	// Generate the final address by encoding the result in Base58 with checksum
	return shaToBase58Check(shaPubKey)
}

// DecodeAddress decodes a Base58 encoded address, validates the checksum, and ensures the correct prefix
// This function reverses the address generation process and checks the integrity of the address
func DecodeAddress(encodedAddress string) ([]byte, error) {
	// Remove the "x" prefix before decoding, if present
	if len(encodedAddress) > 0 && encodedAddress[0] == 'x' {
		encodedAddress = encodedAddress[1:]
	}

	// Decode the Base58 encoded address
	decoded := base58.Decode(encodedAddress)

	// Ensure the decoded address contains the required checksum
	if len(decoded) < 4 {
		return nil, ErrInvalidFormat // Return an error if the address is too short
	}

	// Split the decoded address into the payload (data) and checksum
	payload := decoded[:len(decoded)-4]
	checksum := decoded[len(decoded)-4:]

	// Recreate the prefixed data (with "x" byte) for checksum validation
	prefixedData := append([]byte{prefixByte}, payload...)

	// Calculate the expected checksum from the prefixed data
	expectedChecksum := Checksum(prefixedData)

	// Validate the checksum by comparing it to the one in the decoded address
	if string(checksum) != string(expectedChecksum) {
		return nil, ErrChecksum // Return an error if the checksum is invalid
	}

	// Return the payload (address) without the prefix byte
	return payload, nil
}
