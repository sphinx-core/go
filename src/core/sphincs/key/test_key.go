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
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,q
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

	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
	key "github.com/sphinx-core/go/src/core/sphincs/key/backend"
)

func main() {
	// Initialize the KeyManager with default SPHINCS+ parameters.
	km, err := key.NewKeyManager()
	if err != nil {
		log.Fatalf("Error initializing KeyManager: %v", err)
	}

	// Generate a new SPHINCS key pair.
	sk, pk, err := km.GenerateKey()
	if err != nil {
		log.Fatalf("Error generating keys: %v", err)
	}
	fmt.Println("Keys generated successfully!")

	// Serialize the key pair.
	// Serialize the key pair.
	skBytes, pkBytes, err := km.SerializeKeyPair(sk, pk)
	if err != nil {
		log.Fatalf("Error serializing key pair: %v", err)
	}

	// Print the serialized keys and their sizes.
	fmt.Printf("Serialized private key (%d bytes): %x\n", len(skBytes), skBytes)
	fmt.Printf("Serialized public key (%d bytes): %x\n", len(pkBytes), pkBytes)

	// Deserialize the key pair.
	deserializedSK, deserializedPK, err := km.DeserializeKeyPair(skBytes, pkBytes)
	if err != nil {
		log.Fatalf("Error deserializing key pair: %v", err)
	}
	fmt.Println("Keys deserialized successfully!")

	// Output the deserialized keys to confirm they match the original.
	fmt.Printf("Deserialized private key: SKseed: %x, SKprf: %x, PKseed: %x, PKroot: %x\n",
		deserializedSK.SKseed, deserializedSK.SKprf, deserializedSK.PKseed, deserializedSK.PKroot)

	fmt.Printf("Deserialized public key: PKseed: %x, PKroot: %x\n",
		deserializedPK.PKseed, deserializedPK.PKroot)

	// Confirm the deserialized keys match the original keys using bytes.Equal
	if !bytes.Equal(deserializedSK.SKseed, sk.SKseed) || !bytes.Equal(deserializedSK.SKprf, sk.SKprf) ||
		!bytes.Equal(deserializedSK.PKseed, sk.PKseed) || !bytes.Equal(deserializedSK.PKroot, sk.PKroot) {
		log.Fatal("Deserialized private key does not match original!")
	}

	if !bytes.Equal(deserializedPK.PKseed, pk.PKseed) || !bytes.Equal(deserializedPK.PKroot, pk.PKroot) {
		log.Fatal("Deserialized public key does not match original!")
	}

	fmt.Println("Deserialization check passed! The keys match.")

	// Step 1: Extract SPHINCS+ parameters (use km.Params.Params for the actual *parameters.Parameters object).
	spxParams := km.Params.Params

	// Step 2: Sign a message using the secret key (sk) and parameters.
	message := []byte("Hello, this is a message to be signed!")
	signature := sphincs.Spx_sign(spxParams, message, deserializedSK)
	if signature == nil {
		log.Fatalf("Error signing message")
	}

	// Step 3: Verify the signature using the public key (pk), parameters, message, and signature.
	isValid := sphincs.Spx_verify(spxParams, message, signature, deserializedPK)
	if !isValid {
		log.Fatalf("Signature verification failed!")
	}
	fmt.Println("Signature verified successfully!")
}
