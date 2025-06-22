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
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/sphinx-core/go/src/core/hashtree"
	sigproof "github.com/sphinx-core/go/src/core/proof"
	key "github.com/sphinx-core/go/src/core/sphincs/key/backend"
	sign "github.com/sphinx-core/go/src/core/sphincs/sign/backend"

	"github.com/syndtr/goleveldb/leveldb"
)

// Simulating communication between Alice and Charlie with SPHINCS+ signing and verification
func main() {
	// Clear LevelDB directory to avoid stale timestamp-nonce pairs from previous runs
	// For development only; in production, preserve LevelDB to prevent signature reuse
	err := os.RemoveAll("src/core/sphincs/hashtree/leaves_db")
	if err != nil {
		log.Fatal("Failed to clear LevelDB directory:", err)
	}

	// Create the root_hashtree directory
	err = os.MkdirAll("src/core/sphincs/hashtree", os.ModePerm)
	if err != nil {
		log.Fatal("Failed to create hashtree directory:", err)
	}

	// Open LevelDB for local storage of timestamp-nonce pairs
	db, err := leveldb.OpenFile("src/core/sphincs/hashtree/leaves_db", nil)
	if err != nil {
		log.Fatal("Failed to open LevelDB:", err)
	}
	defer db.Close()

	// Initialize the KeyManager with SPHINCS+ parameters
	km, err := key.NewKeyManager()
	if err != nil {
		log.Fatalf("Error initializing KeyManager: %v", err)
	}

	// Initialize SPHINCS parameters
	parameters := km.GetSPHINCSParameters()

	// Initialize SphincsManager for signing and verification
	manager := sign.NewSphincsManager(db, km, parameters)

	// Generate a new SPHINCS key pair
	sk, pk, err := km.GenerateKey()
	if err != nil {
		log.Fatalf("Error generating keys: %v", err)
	}
	fmt.Println("Keys generated successfully!")

	// Serialize the key pair
	skBytes, pkBytes, err := km.SerializeKeyPair(sk, pk)
	if err != nil {
		log.Fatalf("Error serializing key pair: %v", err)
	}
	fmt.Printf("Serialized private key: %x\n", skBytes)
	fmt.Printf("Size of Serialized private key: %d bytes\n", len(skBytes))
	fmt.Printf("Serialized public key: %x\n", pkBytes)
	fmt.Printf("Size of Serialized public key: %d bytes\n", len(pkBytes))

	// Deserialize the key pair
	deserializedSK, deserializedPK, err := km.DeserializeKeyPair(skBytes, pkBytes)
	if err != nil {
		log.Fatalf("Error deserializing key pair: %v", err)
	}
	fmt.Println("Keys deserialized successfully!")

	// Alice signs the message for tx1 = sig1(proof1(m1, nonce, timestamp, root, pk))
	// Signing is performed locally; tx1 may be submitted to a blockchain for on-chain processing
	message := []byte("Hello, world!")
	// SignMessage generates sig1 with timestamp and nonce to prevent reuse
	sig, merkleRoot, timestamp, nonce, err := manager.SignMessage(message, deserializedSK)
	if err != nil {
		log.Fatal("Failed to sign message:", err)
	}

	// Serialize the signature
	sigBytes, err := manager.SerializeSignature(sig)
	if err != nil {
		log.Fatal("Failed to serialize signature:", err)
	}
	fmt.Printf("Signature (sig1): %x\n", sigBytes)
	fmt.Printf("Size of Serialized Signature: %d bytes\n", len(sigBytes))
	fmt.Printf("Timestamp: %x\n", timestamp)
	fmt.Printf("Nonce: %x\n", nonce)

	// Convert Merkle Root Hash to []byte
	merkleRootHash := merkleRoot.Hash.Bytes()
	fmt.Printf("HashTree (Root Hash): %x\n", merkleRootHash)
	fmt.Printf("Size of HashTree (Root Hash): %d bytes\n", len(merkleRootHash))

	// Save Merkle root hash to a file
	err = hashtree.SaveRootHashToFile(merkleRoot, "src/core/sphincs/hashtree/hashtree.bin")
	if err != nil {
		log.Fatal("Failed to save root hash to file:", err)
	}

	// Generate proof1 for tx1
	// Proof1 binds sig1 to m1, timestamp, nonce, root, and pk
	proof, err := sigproof.GenerateSigProof([][]byte{append(timestamp, append(nonce, message...)...)}, [][]byte{merkleRootHash}, pkBytes)
	if err != nil {
		log.Fatalf("Failed to generate signature proof: %v", err)
	}
	fmt.Printf("Generated Proof (proof1): %x\n", proof)

	// Store the proof locally
	sigproof.SetStoredProof(proof)
	fmt.Println("Signature proof stored successfully!")

	// Alice verifies sig1 locally
	isValidSig := manager.VerifySignature(message, timestamp, nonce, sig, deserializedPK, merkleRoot)
	fmt.Printf("Alice verifies signature valid: %v\n", isValidSig)
	if isValidSig {
		fmt.Printf("Signed Message by Alice: %s\n", message)
	}

	// --- Simulate sending tx1 to Charlie ---
	// In a blockchain, tx1 could be submitted to a smart contract for on-chain verification
	receivedPK := pkBytes
	receivedProof := proof
	receivedMessage := message
	receivedTimestamp := timestamp
	receivedNonce := nonce
	receivedMerkleRootHash := merkleRootHash

	// Charlie’s verification for tx1
	// Performed locally; results may be submitted to a blockchain
	// Check timestamp freshness
	receivedTimestampInt := binary.BigEndian.Uint64(receivedTimestamp)
	currentTimestamp := uint64(time.Now().Unix())
	if currentTimestamp-receivedTimestampInt > 300 { // 5-minute window
		log.Fatal("Signature timestamp is too old, possible reuse attempt")
	}

	// Check for signature reuse
	// No pair exists yet, as we store it only after verification
	exists, err := manager.CheckTimestampNonce(receivedTimestamp, receivedNonce)
	if err != nil {
		log.Fatalf("Failed to check timestamp-nonce pair: %v", err)
	}
	if exists {
		log.Fatal("Signature reuse detected: timestamp-nonce pair already exists")
	}

	// Regenerate proof1
	regeneratedProof, err := sigproof.GenerateSigProof([][]byte{append(receivedTimestamp, append(receivedNonce, receivedMessage...)...)}, [][]byte{receivedMerkleRootHash}, receivedPK)
	if err != nil {
		log.Fatalf("Failed to regenerate proof: %v", err)
	}
	fmt.Printf("Regenerated Proof: %x\n", regeneratedProof)

	// Verify proof1
	isValidProof := sigproof.VerifySigProof(receivedProof, regeneratedProof)
	fmt.Printf("Charlie verifies proof valid: %v\n", isValidProof)

	if isValidProof && isValidSig {
		fmt.Printf("Charlie accepts tx1:\n")
		fmt.Printf("Public Key: %x\n", receivedPK)
		fmt.Printf("Proof: %x\n", receivedProof)
		fmt.Printf("Message: %s\n", receivedMessage)
		fmt.Printf("Timestamp: %x (%d)\n", receivedTimestamp, receivedTimestampInt)
		fmt.Printf("Nonce: %x\n", receivedNonce)
		fmt.Printf("RootHash: %x\n", receivedMerkleRootHash)
		totalSize := len(receivedPK) + len(receivedProof) + len(receivedMessage) + len(receivedTimestamp) + len(receivedNonce) + len(receivedMerkleRootHash)
		fmt.Printf("Total Size in Bytes: %d\n", totalSize)
		// In a blockchain, Charlie could submit tx1 to a smart contract for on-chain verification
	} else {
		fmt.Println("Invalid proof or signature for tx1.")
	}

	// Store timestamp-nonce pair only after verification
	// Prevents "Signature reuse detected" error and ensures reuse prevention
	// In a blockchain, this could be stored in a smart contract
	err = manager.StoreTimestampNonce(receivedTimestamp, receivedNonce)
	if err != nil {
		log.Fatal("Failed to store timestamp-nonce pair:", err)
	}

	// --- Simulate Alice attempting tx2 = sig1(proof2(m2, nonce, timestamp, root, pk)) ---
	// Demonstrates that Alice cannot reuse sig1
	message2 := []byte("Hello, world!")
	// Reuse sig1 with proof2
	proof2, err := sigproof.GenerateSigProof([][]byte{append(timestamp, append(nonce, message2...)...)}, [][]byte{merkleRootHash}, pkBytes)
	if err != nil {
		log.Fatalf("Failed to generate proof for tx2: %v", err)
	}
	fmt.Printf("Generated Proof (proof2): %x\n", proof2)

	// Charlie’s verification for tx2
	receivedMessage2 := message2
	receivedProof2 := proof2

	// Check timestamp freshness
	if currentTimestamp-receivedTimestampInt > 300 {
		log.Println("Signature timestamp for tx2 is too old, rejected")
	} else {
		// Check for signature reuse
		// Detects the timestamp-nonce pair stored for tx1
		exists, err = manager.CheckTimestampNonce(receivedTimestamp, receivedNonce)
		if err != nil {
			log.Fatalf("Failed to check timestamp-nonce pair for tx2: %v", err)
		}
		if exists {
			log.Println("Signature reuse detected for tx2: timestamp-nonce pair already exists")
		}

		// Regenerate proof2
		regeneratedProof2, err := sigproof.GenerateSigProof([][]byte{append(receivedTimestamp, append(receivedNonce, receivedMessage2...)...)}, [][]byte{receivedMerkleRootHash}, receivedPK)
		if err != nil {
			log.Fatalf("Failed to regenerate proof for tx2: %v", err)
		}
		fmt.Printf("Regenerated Proof (proof2): %x\n", regeneratedProof2)

		// Verify proof2
		isValidProof2 := sigproof.VerifySigProof(receivedProof2, regeneratedProof2)
		fmt.Printf("Charlie verifies proof (tx2) valid: %v\n", isValidProof2)

		// Verify sig1 for m2 (will fail due to SPHINCS+ binding)
		isValidSig2 := manager.VerifySignature(receivedMessage2, receivedTimestamp, receivedNonce, sig, deserializedPK, merkleRoot)
		fmt.Printf("Charlie verifies signature (tx2) valid: %v\n", isValidSig2)

		if isValidProof2 && isValidSig2 {
			fmt.Println("Charlie accepts tx2 (this should not happen).")
		} else {
			fmt.Println("Invalid proof or signature for tx2, rejected as expected.")
		}
	}
}
