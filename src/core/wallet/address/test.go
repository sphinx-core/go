package main

import (
	"fmt"
	"log"

	key "github.com/sphinx-core/go/src/core/sphincs/key/backend"
	"github.com/sphinx-core/go/src/encode"
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
