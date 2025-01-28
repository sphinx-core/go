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

package main

import (
	"fmt"
	"log"

	key "github.com/sphinx-core/go/src/core/sphincs/key/backend"
	"github.com/sphinx-core/go/src/core/wallet/address/encode"
)

func main() {
	// Initialize the KeyManager
	keyManager, err := key.NewKeyManager()
	if err != nil {
		log.Fatalf("Failed to initialize KeyManager: %v", err)
	}

	// Generate a new SPHINCS+ key pair
	sk, pk, err := keyManager.GenerateKey()
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}

	// Output the generated private and public keys in byte format
	fmt.Println("Private Key (Serialized):", sk)
	fmt.Println("Public Key (Serialized):", pk)

	// Generate an address from the public key using the encoding package
	address := encode.GenerateAddress(pk.PKseed) // Use PKseed or PKroot as needed
	fmt.Println("Generated Address:", address)

	// Optionally, decode the address back into the public key bytes
	decodedPubKey, err := encode.DecodeAddress(address)
	if err != nil {
		log.Fatalf("Failed to decode address: %v", err)
	}
	fmt.Println("Decoded Public Key:", decodedPubKey)
}
