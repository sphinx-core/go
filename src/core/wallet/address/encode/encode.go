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
	"fmt"

	"github.com/btcsuite/btcutil/base58"
	"github.com/sphinx-core/go/src/common"
	"golang.org/x/crypto/ripemd160"
)

// Prefix byte for address generation
const prefixByte = 0x78 // ASCII 'x'

// pubKeyToHash hashes the public key twice using the SphinxHash algorithm
func pubKeyToHash(pubKey []byte) []byte {
	// First hash using SphinxHash
	firstHash := common.SpxHash(pubKey)
	// Second hash using SphinxHash on the first result
	secondHash := common.SpxHash(firstHash)
	return secondHash
}

// spxToRipemd160 applies RIPEMD-160 hashing to the SphinxHash result
func spxToRipemd160(hashPubKey []byte) []byte {
	ripemd160Hash := ripemd160.New()
	ripemd160Hash.Write(hashPubKey)
	return ripemd160Hash.Sum(nil)
}

// ripemd160ToBase58 encodes the RIPEMD-160 hash with the prefix byte and applies Base58 encoding
func ripemd160ToBase58(ripemd160PubKey []byte) string {
	// Add prefix byte '0x78' (ASCII 'x') to the beginning of the address
	addressBytes := append([]byte{prefixByte}, ripemd160PubKey...)
	// Encode the address in Base58
	return base58.Encode(addressBytes)
}

// GenerateAddress generates an address from a public key by applying SphinxHash, RIPEMD-160, and Base58 encoding
func GenerateAddress(pubKey []byte) string {
	// Step 1: Apply double hashing (SphinxHash) to the public key
	hashedPubKey := pubKeyToHash(pubKey)

	// Step 2: Apply RIPEMD-160 hashing to the result of the double hash
	ripemd160PubKey := spxToRipemd160(hashedPubKey)

	// Step 3: Encode the address in Base58
	return ripemd160ToBase58(ripemd160PubKey)
}

// DecodeAddress decodes a Base58 encoded address and checks for the correct prefix byte
func DecodeAddress(encodedAddress string) ([]byte, error) {
	// Decode the Base58 encoded address using base58.Decode
	addressBytes := base58.Decode(encodedAddress)

	if len(addressBytes) == 0 {
		return nil, fmt.Errorf("invalid address: %s", encodedAddress)
	}

	// Check for the correct prefix byte (0x78)
	if addressBytes[0] != prefixByte {
		return nil, fmt.Errorf("invalid address prefix")
	}

	// Return the address without the prefix byte
	return addressBytes[1:], nil
}
