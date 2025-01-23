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

// Simulating the communication between Alice and Charlie
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

	// Alice signs the message
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

	// Generate the proof for Charlie to verify
	proof, err := sigproof.GenerateSigProof([][]byte{message}, [][]byte{merkleRootHash})
	if err != nil {
		log.Fatalf("Failed to generate signature proof: %v", err)
	}
	fmt.Printf("Generated Proof: %x\n", proof)

	// Store the proof for Charlie to use
	sigproof.SetStoredProof(proof)
	fmt.Println("Signature proof stored successfully in mutex-protected variable!")

	// Now Alice verifies the signature locally:
	isValidSig := manager.VerifySignature(message, sig, deserializedPK, merkleRoot)
	fmt.Printf("Alice verifies signature valid: %v\n", isValidSig)
	if isValidSig {
		fmt.Printf("Signed Message by alice: %s\n", message)
	}

	// --- Simulate sending data from Alice to Charlie ---
	// Example: Alice sends pkBytes, proof, and message to Charlie
	// In a real application, use network communication (e.g., HTTP, gRPC) to send these values.

	// --- Charlie's side ---
	// Charlie receives the public key, proof, and message
	receivedPK := pkBytes
	receivedProof := proof
	receivedMessage := message

	// Deserialize the public key for Charlie
	receivedDeserializedPK, err := km.DeserializePublicKey(receivedPK)
	if err != nil {
		log.Fatalf("Error deserializing received public key: %v", err)
	}

	// Verify the proof received by Charlie
	isValidProof := sigproof.VerifySigProof(receivedProof, proof)
	fmt.Printf("Charlie verifies proof valid: %v\n", isValidProof)

	// Charlie verifies the signature with the received public key and proof
	if isValidProof {
		isValidSig := manager.VerifySignature(receivedMessage, sig, receivedDeserializedPK, merkleRoot)
		fmt.Printf("Charlie verifies signature valid: %v\n", isValidSig)
		if isValidSig {
			fmt.Printf("Verified message: %s\n", receivedMessage)
		} else {
			fmt.Println("Invalid signature.")
		}
	} else {
		fmt.Println("Invalid proof.")
	}
	// Print actual values during verification in Charlie's hardware
	fmt.Printf("What Charlie loads into his hardware?:\n")
	fmt.Printf("Alice's Public key: %x\n", receivedPK)
	fmt.Printf("Alice's Proof: %x\n", receivedProof)
	fmt.Printf("Alice's message: %s\n", receivedMessage)
	fmt.Printf("Alice's HashTree (Root Hash): %x\n", merkleRootHash)
}
