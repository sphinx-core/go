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

package wots

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// Defines the GenerateKeyPair function that takes WOTSParams and returns private key, public key, and error
func GenerateKeyPair(params WOTSParams) (*PrivateKey, *PublicKey, error) {
	// Creates a slice of T byte slices for the private key, where T is the number of hash chains
	privKey := make([][]byte, params.T)
	// Loops through each of the T private key components
	for i := 0; i < params.T; i++ {
		// Allocates a byte slice of length N (32 bytes for SHAKE256) for the i-th private key component
		privKey[i] = make([]byte, params.N)
		// Fills the i-th private key component with random bytes using crypto/rand
		_, err := rand.Read(privKey[i])
		// Checks if there was an error during random number generation
		if err != nil {
			// Returns nil for both keys and an error if random generation failed
			return nil, nil, fmt.Errorf("failed to generate random private key: %v", err)
		}
	}

	// Creates a slice of T byte slices for the public key, corresponding to T hash chains
	pubKey := make([][]byte, params.T)
	// Calculates the maximum number of hashes per chain (w-1, which is 15 for w=16)
	maxHashes := params.W - 1
	// Loops through each of the T public key components
	for i := 0; i < params.T; i++ {
		// Allocates a byte slice of length N (32 bytes) for the i-th public key component
		pubKey[i] = make([]byte, params.N)
		// Copies the i-th private key component to the i-th public key component as the starting point
		copy(pubKey[i], privKey[i])
		// Loops maxHashes times to compute the public key by hashing the private key component
		for j := 0; j < maxHashes; j++ {
			// Allocates a byte slice of length N to store the hash output
			hash := make([]byte, params.N)
			// Computes the SHAKE256 hash of the current public key component and stores it in hash
			sha3.ShakeSum256(hash, pubKey[i])
			// Updates the i-th public key component with the hash result
			copy(pubKey[i], hash)
		}
	}

	// Returns a pointer to the PrivateKey struct with the given params and privKey
	return &PrivateKey{Params: params, Key: privKey},
		// Returns a pointer to the PublicKey struct with the given params and pubKey
		&PublicKey{Params: params, Key: pubKey},
		// Returns nil for the error, indicating successful key generation
		nil
}

// Defines the Sign method on PrivateKey, taking a message and returning a signature and error
func (sk *PrivateKey) Sign(message []byte) (*Signature, error) {
	// Allocates a byte slice of length N (32 bytes) to store the message hash
	msgHash := make([]byte, sk.Params.N)
	// Computes the SHAKE256 hash of the input message and stores it in msgHash
	sha3.ShakeSum256(msgHash, message)

	// Retrieves the WOTS parameters from the private key
	params := sk.Params
	// Sets logW to 4, as log2(16) = 4 for w=16
	logW := 4

	// Allocates a slice of T1 integers to store the base-w representation of the message hash
	baseW := make([]int, params.T1)
	// Loops through T1 iterations to convert the message hash to base-16 digits
	for i := 0; i < params.T1; i++ {
		// Calculates the starting bit position for the i-th digit (i * 4 bits)
		startBit := i * logW
		// Determines the starting byte index in msgHash
		startByte := startBit / 8
		// Calculates the bit offset within the starting byte
		bitOffset := startBit % 8
		// Declarates a variable to store the extracted digit value
		var value int
		// Checks if the digit fits within a single byte (bitOffset + 4 <= 8)
		if bitOffset+logW <= 8 {
			// Extracts 4 bits from the byte, shifted and masked to get a value in [0, 15]
			value = int((msgHash[startByte] >> (8 - bitOffset - logW)) & 0x0F)
			// Handles the case where the digit spans two bytes
		} else {
			// Combines bits from two bytes to form the digit
			value = int((msgHash[startByte] << bitOffset) | (msgHash[startByte+1] >> (16 - bitOffset - logW)))
			// Masks the value to ensure it is in [0, 15]
			value &= 0x0F
		}
		// Stores the extracted digit in the baseW slice
		baseW[i] = value
	}

	// Initializes the checksum value to 0
	checksum := 0
	// Sets maxValue to w-1 (15 for w=16), the maximumwt value of a base-w digit
	maxValue := params.W - 1
	// Loops through each base-w digit
	for _, v := range baseW {
		// Adds (maxValue - digit) to the checksum to ensure signature security
		checksum += maxValue - v
	}

	// Allocates a slice of T2 integers for the base-w representation of the checksum
	checksumBaseW := make([]int, params.T2)
	// Loops backward through T2 positions to extract checksum digits
	for i := params.T2 - 1; i >= 0; i-- {
		// Extracts the least significant 4 bits of the checksum as a digit
		checksumBaseW[i] = checksum & 0x0F
		// Right-shifts the checksum by 4 bits to process the next digit
		checksum >>= logW
	}

	// Concatenates the message digits (baseW) and checksum digits (checksumBaseW) into a single slice
	combined := append(baseW, checksumBaseW...)

	// Allocates a slice of T byte slices for the signature
	sig := make([][]byte, params.T)
	// Loops through each of the T signature components
	for i := 0; i < params.T; i++ {
		// Allocates a byte slice of length N (32 bytes) for the i-th signature component
		sig[i] = make([]byte, params.N)
		// Copies the i-th private key component to the i-th signature component as the starting point
		copy(sig[i], sk.Key[i])
		// Loops combined[i] times to hash the signature component
		for j := 0; j < combined[i]; j++ {
			// Allocates a byte slice of length N to store the hash output
			hash := make([]byte, params.N)
			// Computes the SHAKE256 hash of the current signature component
			sha3.ShakeSum256(hash, sig[i])
			// Updates the i-th signature component with the hash result
			copy(sig[i], hash)
		}
	}

	// Returns a pointer to the Signature struct with params and sig, and nil error
	return &Signature{Params: params, Sig: sig}, nil
}

// Defines the Verify method on PublicKey, taking a message and signature, returning a boolean and error
func (pk *PublicKey) Verify(message []byte, sig *Signature) (bool, error) {
	// Checks if the signature parameters match the public key parameters
	if sig.Params != pk.Params {
		// Returns false and an error if parameters do not match
		return false, fmt.Errorf("signature parameters do not match public key parameters")
	}

	// Allocates a byte slice of length N (32 bytes) to store the message hash
	msgHash := make([]byte, pk.Params.N)
	// Computes the SHAKE256 hash of the input message and stores it in msgHash
	sha3.ShakeSum256(msgHash, message)

	// Retrieves the WOTS parameters from the public key
	params := pk.Params
	// Sets logW to 4, as log2(16) = 4 for w=16
	logW := 4

	// Allocates a slice of T1 integers for the base-w representation of the message hash
	baseW := make([]int, params.T1)
	// Loops through T1 iterations to convert the message hash to base-16 digits
	for i := 0; i < params.T1; i++ {
		// Calculates the starting bit position for the i-th digit (i * 4 bits)
		startBit := i * logW
		// Determines the starting byte index in msgHash
		startByte := startBit / 8
		// Calculates the bit offset within the starting byte
		bitOffset := startBit % 8
		// Declares a variable to store the extracted digit value
		var value int
		// Checks if the digit fits within a single byte (bitOffset + 4 <= 8)
		if bitOffset+logW <= 8 {
			// Extracts 4 bits from the byte, shifted and masked to get a value in [0, 15]
			value = int((msgHash[startByte] >> (8 - bitOffset - logW)) & 0x0F)
			// Handles the case where the digit spans two bytes
		} else {
			// Combines bits from two bytes to form the digit
			value = int((msgHash[startByte] << bitOffset) | (msgHash[startByte+1] >> (16 - bitOffset - logW)))
			// Masks the value to ensure it is in [0, 15]
			value &= 0x0F
		}
		// Stores the extracted digit in the baseW slice
		baseW[i] = value
	}

	// Initializes the checksum value to 0
	checksum := 0
	// Sets maxValue to w-1 (15 for w=16), the maximum value of a base-w digit
	maxValue := params.W - 1
	// Loops through each base-w digit
	for _, v := range baseW {
		// Adds (maxValue - digit) to the checksum to ensure signature security
		checksum += maxValue - v
	}

	// Allocates a slice of T2 integers for the base-w representation of the checksum
	checksumBaseW := make([]int, params.T2)
	// Loops backward through T2 positions to extract checksum digits
	for i := params.T2 - 1; i >= 0; i-- {
		// Extracts the least significant 4 bits of the checksum as a digit
		checksumBaseW[i] = checksum & 0x0F
		// Right-shifts the checksum by 4 bits to process the next digit
		checksum >>= logW
	}

	// Concatenates the message digits (baseW) and checksum digits (checksumBaseW) into a single slice
	combined := append(baseW, checksumBaseW...)

	// Loops through each of the T signature components
	for i := 0; i < params.T; i++ {
		// Calculates the number of hashes needed to reach the public key (maxValue - digit)
		numHashes := maxValue - combined[i]
		// Allocates a byte slice of length N (32 bytes) to store the current hash state
		current := make([]byte, params.N)
		// Copies the i-th signature component to current as the starting point
		copy(current, sig.Sig[i])
		// Loops numHashes times to hash toward the public key
		for j := 0; j < numHashes; j++ {
			// Allocates a byte slice of length N to store the hash output
			hash := make([]byte, params.N)
			// Computes the SHAKE256 hash of the current state
			sha3.ShakeSum256(hash, current)
			// Updates current with the hash result
			copy(current, hash)
		}
		// Loops through each byte of the hashed result
		for j := 0; j < params.N; j++ {
			// Compares the hashed result with the i-th public key component
			if current[j] != pk.Key[i][j] {
				// Returns false and nil error if any byte does not match
				return false, nil
			}
		}
	}

	// Returns true and nil error, indicating the signature is valid
	return true, nil
}
