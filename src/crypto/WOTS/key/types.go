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

// WOTSParams holds Winternitz parameters
type WOTSParams struct {
	W        int // Winternitz parameter (fixed to 16)
	N        int // Hash output size in bytes (32 for SHAKE256)
	T        int // Number of hash chains
	T1       int // Length of message chains
	T2       int // Length of checksum chains
	Checksum int // Checksum size in bits
}

// PrivateKey represents a WOTS private key
type PrivateKey struct {
	Params WOTSParams
	Key    [][]byte // T random values of length N
}

// PublicKey represents a WOTS public key
type PublicKey struct {
	Params WOTSParams
	Key    [][]byte // T hashed values of length N
}

// Signature represents a WOTS signature
type Signature struct {
	Params WOTSParams
	Sig    [][]byte // T values of length N
}

// KeyManager manages WOTS key pairs for Alice
type KeyManager struct {
	Params    WOTSParams
	CurrentSK *PrivateKey // Current private key
	CurrentPK *PublicKey  // Current public key
	NextPK    *PublicKey  // Public key for next transaction (optional)
}
