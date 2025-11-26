// Copyright 2024 Lei Ni (nilei81@gmail.com)
//
// This library follows a dual licensing model -
//
// - it is licensed under the 2-clause BSD license if you have written evidence showing that you are a licensee of github.com/lni/pothos
// - otherwise, it is licensed under the GPL-2 license
//
// See the LICENSE file for details
//
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

// go/src/network/key.go
package network

import (
	"crypto/rand"

	"encoding/hex"
	"fmt"

	database "github.com/sphinx-core/go/src/core/state"
	"lukechampine.com/blake3"
)

// SimpleKeyManager provides basic key management functionality
type SimpleKeyManager struct{}

// GenerateKey generates a simple key pair (placeholder implementation)
func (skm *SimpleKeyManager) GenerateKey() ([]byte, []byte, error) {
	// Generate random keys (in production, use proper cryptographic key generation)
	privateKey := make([]byte, 32)
	publicKey := make([]byte, 32)

	if _, err := rand.Read(privateKey); err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	if _, err := rand.Read(publicKey); err != nil {
		return nil, nil, fmt.Errorf("failed to generate public key: %w", err)
	}

	return privateKey, publicKey, nil
}

// SerializeKeyPair simply returns the keys as-is
func (skm *SimpleKeyManager) SerializeKeyPair(privateKey, publicKey []byte) ([]byte, []byte, error) {
	return privateKey, publicKey, nil
}

// NewSimpleNetworkKeyManager creates a new key manager with simple implementation
func NewSimpleNetworkKeyManager(db *database.DB) (*NetworkKeyManager, error) {
	return &NetworkKeyManager{
		db:         db,
		keyManager: &SimpleKeyManager{},
	}, nil
}

// GenerateSimpleKeys generates keys using the simple key manager
func (nkm *NetworkKeyManager) GenerateSimpleKeys() ([]byte, []byte, error) {
	if skm, ok := nkm.keyManager.(*SimpleKeyManager); ok {
		return skm.GenerateKey()
	}
	return nil, nil, fmt.Errorf("key manager not available")
}

// SerializeSimpleKeys serializes keys using the simple key manager
func (nkm *NetworkKeyManager) SerializeSimpleKeys(privateKey, publicKey []byte) ([]byte, []byte, error) {
	if skm, ok := nkm.keyManager.(*SimpleKeyManager); ok {
		return skm.SerializeKeyPair(privateKey, publicKey)
	}
	return nil, nil, fmt.Errorf("key manager not available")
}

// IsEmpty checks if the key is zero.
func (k Key) IsEmpty() bool {
	for _, b := range k {
		if b != 0 {
			return false
		}
	}
	return true
}

// Short returns a shortened hexadecimal string of the last 16 bits.
func (k Key) Short() string {
	return fmt.Sprintf("%04x", uint16(k[30])<<8|uint16(k[31]))
}

// String returns a full hexadecimal string of the key.
func (k Key) String() string {
	return hex.EncodeToString(k[:])
}

// Equal compares two keys for equality.
func (k Key) Equal(other Key) bool {
	return k == other
}

// Less compares two keys lexicographically.
func (k Key) Less(other Key) bool {
	for i := 0; i < 32; i++ {
		if k[i] < other[i] {
			return true
		} else if k[i] > other[i] {
			return false
		}
	}
	return false
}

// leadingZeroBits counts the number of leading zero bits in the key.
func (k Key) leadingZeroBits() int {
	count := 0
	for _, b := range k {
		if b == 0 {
			count += 8
			continue
		}
		for i := 7; i >= 0; i-- {
			if b&(1<<i) == 0 {
				count++
			} else {
				break
			}
		}
		break
	}
	return count
}

// CommonPrefixLength computes the number of leading bits shared with another key.
func (k Key) CommonPrefixLength(other Key) int {
	var r Key
	r.Distance(k, other)
	return r.leadingZeroBits()
}

// Distance sets k as the XOR result of a and b.
func (k *Key) Distance(a, b Key) {
	for i := 0; i < 32; i++ {
		k[i] = a[i] ^ b[i]
	}
}

// FromNodeID copies a nodeID into the key.
func (k *Key) FromNodeID(other nodeID) {
	*k = other
}

// FromString generates a 256-bit key by hashing the input string with BLAKE3.
// Returns an error instead of panicking.
func (k *Key) FromString(v string) error {
	hash := blake3.Sum256([]byte(v))
	if len(k) < len(hash) {
		return fmt.Errorf("key size too small: need %d bytes, have %d", len(hash), len(k))
	}
	copy(k[:], hash[:])
	return nil
}

// GenerateKademliaID generates a 256-bit Kademlia ID by hashing the input string.
func GenerateKademliaID(input string) NodeID {
	var k Key
	k.FromString(input)
	return NodeID(k)
}

// GetRandomNodeID generates a random 256-bit nodeID.
func GetRandomNodeID() NodeID {
	var k Key
	_, err := rand.Read(k[:])
	if err != nil {
		panic(err)
	}
	return NodeID(k)
}
