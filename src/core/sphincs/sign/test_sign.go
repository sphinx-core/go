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
	"fmt"
	"log"
	"os"

	"github.com/sphinx-core/go/src/core/hashtree"
	sigproof "github.com/sphinx-core/go/src/core/proof"
	key "github.com/sphinx-core/go/src/core/sphincs/key/backend"
	sign "github.com/sphinx-core/go/src/core/sphincs/sign/backend"
	"github.com/syndtr/goleveldb/leveldb"
)

// Message: The original data (the message "Hello, world!") that is being signed.
// Merkle Root Hash: The root hash of the Merkle tree that was generated when signing the message.
// Proof Generation: GenerateSigProof takes these inputs and creates a proof that confirms the validity of the signature (i.e., that the signature corresponds to the message and the Merkle root).

func main() {
	// Create the root_hashtree directory inside src/core
	err := os.MkdirAll("root_hashtree", os.ModePerm)
	if err != nil {
		log.Fatal("Failed to create root_hashtree directory:", err)
	}

	// Open LevelDB in the new directory
	db, err := leveldb.OpenFile("root_hashtree/leaves_db", nil)
	if err != nil {
		log.Fatal("Failed to open LevelDB:", err)
	}
	defer db.Close()

	// Initialize the KeyManager with default SPHINCS+ parameters.
	km, err := key.NewKeyManager()
	if err != nil {
		log.Fatalf("Error initializing KeyManager: %v", err)
	}

	// Initialize the SPHINCS parameters (you might need to fetch or generate them)
	parameters := km.GetSPHINCSParameters()

	// Initialize the SphincsManager with the LevelDB instance, KeyManager, and SPHINCSParameters
	manager := sign.NewSphincsManager(db, km, parameters)

	// Generate a new SPHINCS key pair.
	sk, pk, err := km.GenerateKey()
	if err != nil {
		log.Fatalf("Error generating keys: %v", err)
	}
	fmt.Println("Keys generated successfully!")

	// Serialize the key pair.
	skBytes, pkBytes, err := km.SerializeKeyPair(sk, pk)
	if err != nil {
		log.Fatalf("Error serializing key pair: %v", err)
	}

	// Print the size of the serialized keys
	fmt.Printf("Serialized private key: %x\n", skBytes)
	fmt.Printf("Size of Serialized private key: %d bytes\n", len(skBytes))

	fmt.Printf("Serialized public key: %x\n", pkBytes)
	fmt.Printf("Size of Serialized public key: %d bytes\n", len(pkBytes))

	// Deserialize the key pair.
	deserializedSK, deserializedPK, err := km.DeserializeKeyPair(skBytes, pkBytes)
	if err != nil {
		log.Fatalf("Error deserializing key pair: %v", err)
	}
	fmt.Println("Keys deserialized successfully!")

	// Sign a message with the deserialized keys
	message := []byte("Hello, world!")
	sig, merkleRoot, err := manager.SignMessage(message, deserializedSK)
	if err != nil {
		log.Fatal("Failed to sign message:", err)
	}

	// Serialize the signature to bytes
	sigBytes, err := manager.SerializeSignature(sig)
	if err != nil {
		log.Fatal("Failed to serialize signature:", err)
	}
	fmt.Printf("Signature: %x\n", sigBytes)
	fmt.Printf("Size of Serialized Signature: %d bytes\n", len(sigBytes))

	// Convert Merkle Root Hash to []byte
	merkleRootHash := merkleRoot.Hash.Bytes()

	// Print Merkle Tree root hash and size
	fmt.Printf("HashTree (Root Hash): %x\n", merkleRootHash)
	fmt.Printf("Size of HashtreeTree (Root Hash): %d bytes\n", len(merkleRootHash))

	// Save Merkle root hash to a file in the new directory
	err = hashtree.SaveRootHashToFile(merkleRoot, "root_hashtree/merkle_root_hash.bin")
	if err != nil {
		log.Fatal("Failed to save root hash to file:", err)
	}

	// Load Merkle root hash from the file
	loadedHash, err := hashtree.LoadRootHashFromFile("root_hashtree/merkle_root_hash.bin")
	if err != nil {
		log.Fatal("Failed to load root hash from file:", err)
	}
	fmt.Printf("Loaded HashTree (Root Hash): %x\n", loadedHash)
	fmt.Printf("Size of Loaded HashTree (Root Hash): %d bytes\n", len(loadedHash))

	// Save leaves to LevelDB
	leaves := [][]byte{sigBytes} // Example usage
	err = hashtree.SaveLeavesToDB(db, leaves)
	if err != nil {
		log.Fatal("Failed to save leaves to DB:", err)
	}

	// Combine the message and Merkle root hash into a proof
	proof, err := sigproof.GenerateSigProof([][]byte{message}, [][]byte{merkleRootHash})
	if err != nil {
		log.Fatalf("Failed to generate signature proof: %v", err)
	}
	fmt.Printf("Generated Proof: %x\n", proof)

	// Store the proof in LevelDB
	err = db.Put([]byte("signature_proof"), proof, nil)
	if err != nil {
		log.Fatalf("Failed to store signature proof: %v", err)
	}
	fmt.Println("Signature proof saved successfully!")

	// Load the proof from LevelDB
	storedProof, err := db.Get([]byte("signature_proof"), nil)
	if err != nil {
		log.Fatalf("Failed to load signature proof: %v", err)
	}
	fmt.Printf("Loaded signature proof: %x\n", storedProof)

	// Verify the proof by comparing it with the generated proof
	isValidProof := sigproof.VerifySigProof(storedProof, proof)
	fmt.Printf("Proof valid: %v\n", isValidProof)

	// Verify the signature and print the original message
	isValid := manager.VerifySignature(message, sig, deserializedPK, merkleRoot)
	fmt.Printf("Signature valid: %v\n", isValid)
	if isValid {
		fmt.Printf("Original Message: %s\n", message)
	}

	// Print the number of bytes loaded during verification
	fmt.Printf("Bytes loaded during verification: Signature: %d bytes, HashTree (root hash): %d bytes\n", len(sigBytes), len(loadedHash))
}
