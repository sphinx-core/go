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
	"bytes"
	"fmt"
	"log"

	key "github.com/sphinx-core/go/src/core/sphincs/key/backend"
	encode "github.com/sphinx-core/go/src/core/wallet/address/encoding"
)

func main() {
	// Initialize SPHINCS+ KeyManager
	km, err := key.NewKeyManager()
	if err != nil {
		log.Fatalf("Error initializing KeyManager: %v", err)
	}

	// Generate SPHINCS+ key pair
	sk, pk, err := km.GenerateKey()
	if err != nil {
		log.Fatalf("Error generating keys: %v", err)
	}
	fmt.Println("✅ Keys generated successfully!")

	// Serialize keys
	skBytes, pkBytes, err := km.SerializeKeyPair(sk, pk)
	if err != nil {
		log.Fatalf("Error serializing keys: %v", err)
	}

	// Print Secret Key details
	fmt.Printf("\n🔐 Serialized Secret Key (%d bytes):\n%x\n", len(skBytes), skBytes)

	// Print raw SPHINCS+ SK components
	fmt.Printf("SKseed (%d bytes): %x\n", len(sk.SKseed), sk.SKseed)
	fmt.Printf("SKprf  (%d bytes): %x\n", len(sk.SKprf), sk.SKprf)
	fmt.Printf("PKseed (%d bytes): %x\n", len(sk.PKseed), sk.PKseed)
	fmt.Printf("PKroot (%d bytes): %x\n", len(sk.PKroot), sk.PKroot)

	// Print Public Key details
	fmt.Printf("\n🟢 Serialized Public Key (%d bytes):\n%x\n", len(pkBytes), pkBytes)
	fmt.Printf("PKseed (%d bytes): %x\n", len(pk.PKseed), pk.PKseed)
	fmt.Printf("PKroot (%d bytes): %x\n", len(pk.PKroot), pk.PKroot)

	// Deserialize and validate keys
	deserializedSK, deserializedPK, err := km.DeserializeKeyPair(skBytes, pkBytes)
	if err != nil {
		log.Fatalf("Error deserializing keys: %v", err)
	}
	if !bytes.Equal(deserializedSK.SKseed, sk.SKseed) ||
		!bytes.Equal(deserializedSK.SKprf, sk.SKprf) ||
		!bytes.Equal(deserializedSK.PKseed, sk.PKseed) ||
		!bytes.Equal(deserializedSK.PKroot, sk.PKroot) {
		log.Fatal("❌ Deserialized private key does not match original!")
	}
	if !bytes.Equal(deserializedPK.PKseed, pk.PKseed) ||
		!bytes.Equal(deserializedPK.PKroot, pk.PKroot) {
		log.Fatal("❌ Deserialized public key does not match original!")
	}

	fmt.Println("\n✅ Keys verified after deserialization")

	// Generate address
	address := encode.GenerateAddress(pk.PKseed)
	fmt.Printf("\n🏷️  Generated Address: %s\n", address)

	// Decode back and show hashed pubkey
	decodedPubKey, err := encode.DecodeAddress(address)
	if err != nil {
		log.Fatalf("Error decoding address: %v", err)
	}
	fmt.Printf("🔒 Hashed Public Key (%d bytes): %x\n", len(decodedPubKey), decodedPubKey)
}
