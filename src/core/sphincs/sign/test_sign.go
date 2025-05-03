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
	// Create the root_hashtree directory inside src/core/sphincs
	err := os.MkdirAll("src/core/sphincs/hashtree", os.ModePerm)
	if err != nil {
		log.Fatal("Failed to create hashtree directory:", err)
	}

	// Open LevelDB in the new directory
	db, err := leveldb.OpenFile("src/core/sphincs/hashtree/leaves_db", nil)
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
	err = hashtree.SaveRootHashToFile(merkleRoot, "src/core/sphincs/hashtree/hashtree.bin")
	if err != nil {
		log.Fatal("Failed to save root hash to file:", err)
	}

	// Generate the proof for Charlie to verify, including pkBytes in the process
	proof, err := sigproof.GenerateSigProof([][]byte{message}, [][]byte{merkleRootHash}, pkBytes)
	if err != nil {
		log.Fatalf("Failed to generate signature proof: %v", err)
	}
	fmt.Printf("Generated Proof: %x\n", proof)

	// Store the proof for Charlie to use
	sigproof.SetStoredProof(proof)
	fmt.Println("Signature proof stored successfully in mutex-protected variable!")

	// Now Alice verifies the signature locally (using her device):
	isValidSig := manager.VerifySignature(message, sig, deserializedPK, merkleRoot)
	fmt.Printf("Alice verifies signature valid: %v\n", isValidSig)
	if isValidSig {
		fmt.Printf("Signed Message by Alice: %s\n", message)
	}

	// --- Simulate sending data from Alice to Charlie ---
	// Example: Alice sends pkBytes, proof, and message to Charlie
	// In a real application, use network communication (e.g., HTTP, gRPC) to send these values.

	// Charlie's side
	// Charlie receives the public key, proof, and message
	receivedPK := pkBytes
	receivedProof := proof
	receivedMessage := message

	// Charlie re-generates the proof from Alice's received message, Merkle root hash, and Public key
	regeneratedProof, err := sigproof.GenerateSigProof([][]byte{receivedMessage}, [][]byte{merkleRootHash}, receivedPK)
	if err != nil {
		log.Fatalf("Failed to regenerate proof: %v", err)
	}

	// Print the regenerated proof
	fmt.Printf("Regenerated Proof: %x\n", regeneratedProof)

	// Verify the proof received by Charlie
	isValidProof := sigproof.VerifySigProof(receivedProof, regeneratedProof)
	fmt.Printf("Charlie verifies proof valid: %v\n", isValidProof)

	// Charlie does NOT verify the signature anymore; only verifies the proof
	if isValidProof {
		// Print everything that Charlie loaded
		fmt.Printf("Charlie has received and loaded:\n")
		fmt.Printf("Alice's Public Key: %x\n", receivedPK)   // Print the public key in hex format
		fmt.Printf("Alice's Proof: %x\n", receivedProof)     // Print the proof in hex format
		fmt.Printf("Alice's Message: %s\n", receivedMessage) // Print the received message
		fmt.Printf("Alice's RootHash: %x\n", merkleRootHash) // Corrected fmt.Printf here

		// Print total size in bytes
		totalSize := len(receivedPK) + len(receivedProof) + len(receivedMessage) + len(merkleRootHash)
		fmt.Printf("Total Size in Bytes: %d\n", totalSize) // Output the total size
	} else {
		// Do not print anything when the proof is invalid
		fmt.Println("Invalid proof.")
	}
}
