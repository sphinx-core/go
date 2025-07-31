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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

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

// FromString generates a 256-bit key by hashing the input string with SHA-256.
func (k *Key) FromString(v string) {
	h := sha256.New()
	if _, err := io.WriteString(h, v); err != nil {
		panic(err)
	}
	copy(k[:], h.Sum(nil))
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
