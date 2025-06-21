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
	"encoding/binary" // Add for timestamp decoding
	"fmt"
	"log"
	"os"
	"time" // Add for timestamp validation

	"github.com/sphinx-core/go/src/core/hashtree"
	sigproof "github.com/sphinx-core/go/src/core/proof"
	key "github.com/sphinx-core/go/src/core/sphincs/key/backend"
	sign "github.com/sphinx-core/go/src/core/sphincs/sign"
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
	// SignMessage now returns timestamp and nonce to prevent signature reuse
	// The timestamp binds the signature to a specific time, ensuring it cannot be reused later
	// The nonce ensures each signature is unique, even for identical messages
	sig, merkleRoot, timestamp, nonce, err := manager.SignMessage(message, deserializedSK)
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
	fmt.Printf("Timestamp: %x\n", timestamp)
	fmt.Printf("Nonce: %x\n", nonce)

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

	// Store timestamp-nonce pair in LevelDB to prevent reuse
	// Charlie will check this to ensure Alice cannot reuse the signature
	// The unique timestamp-nonce pair ensures that even if Alice tries to replay the signature,
	// Charlie will detect the duplicate and reject it
	timestampNonce := append(timestamp, nonce...)
	err = db.Put(timestampNonce, []byte("seen"), nil)
	if err != nil {
		log.Fatal("Failed to store timestamp-nonce pair:", err)
	}

	// Generate the proof for Charlie to verify, including pkBytes in the process
	// The proof includes the message, Merkle root hash, and public key
	// This ensures Alice cannot claim the signature was for a different message or key
	proof, err := sigproof.GenerateSigProof([][]byte{append(timestamp, append(nonce, message...)...)}, [][]byte{merkleRootHash}, pkBytes)
	if err != nil {
		log.Fatalf("Failed to generate signature proof: %v", err)
	}
	fmt.Printf("Generated Proof: %x\n", proof)

	// Store the proof for Charlie to use
	sigproof.SetStoredProof(proof)
	fmt.Println("Signature proof stored successfully in mutex-protected variable!")

	// Now Alice verifies the signature locally (using her device):
	// Local verification ensures the signature is valid before sending to Charlie
	isValidSig := manager.VerifySignature(message, timestamp, nonce, sig, deserializedPK, merkleRoot)
	fmt.Printf("Alice verifies signature valid: %v\n", isValidSig)
	if isValidSig {
		fmt.Printf("Signed Message by Alice: %s\n", message)
	}

	// --- Simulate sending data from Alice to Charlie ---
	// Example: Alice sends pkBytes, proof, message, timestamp, nonce, and Merkle root hash to Charlie
	// In a real application, use network communication (e.g., HTTP, gRPC) to send these values.
	// The timestamp and nonce are sent to Charlie to prevent reuse
	// Alice cannot lie about reuse because Charlie will verify the timestamp and nonce

	// Charlie's side
	// Charlie receives the public key, proof, message, timestamp, nonce, and Merkle root hash
	receivedPK := pkBytes
	receivedProof := proof
	receivedMessage := message
	receivedTimestamp := timestamp
	receivedNonce := nonce
	receivedMerkleRootHash := merkleRootHash

	// Charlie checks timestamp freshness (e.g., within 5 minutes)
	// This prevents Alice from reusing an old signature, as Charlie will reject outdated timestamps
	receivedTimestampInt := binary.BigEndian.Uint64(receivedTimestamp)
	currentTimestamp := uint64(time.Now().Unix())
	if currentTimestamp-receivedTimestampInt > 300 { // 5-minute window
		log.Fatal("Signature timestamp is too old, possible reuse attempt")
	}

	// Charlie checks if timestamp-nonce pair was seen before
	// This prevents Alice from reusing a signature, as the unique timestamp-nonce pair
	// will already be stored in LevelDB if the signature was used previously
	if _, err := db.Get(append(receivedTimestamp, receivedNonce...), nil); err == nil {
		log.Fatal("Signature reuse detected: timestamp-nonce pair already exists")
	}

	// Charlie re-generates the proof from Alice's received message, timestamp, nonce, Merkle root hash, and public key
	// The proof ensures the signature corresponds to the specific message and key
	// Alice cannot lie about the message or key used, as the proof will not match
	regeneratedProof, err := sigproof.GenerateSigProof([][]byte{append(receivedTimestamp, append(receivedNonce, receivedMessage...)...)}, [][]byte{receivedMerkleRootHash}, receivedPK)
	if err != nil {
		log.Fatalf("Failed to regenerate proof: %v", err)
	}

	// Print the regenerated proof
	fmt.Printf("Regenerated Proof: %x\n", regeneratedProof)

	// Verify the proof received by Charlie
	// The proof verification ensures the integrity of the message, timestamp, nonce, and public key
	// If Alice tries to lie about the signature's origin or reuse it, the proof will not match
	isValidProof := sigproof.VerifySigProof(receivedProof, regeneratedProof)
	fmt.Printf("Charlie verifies proof valid: %v\n", isValidProof)

	// Charlie verifies the signature using the received timestamp and nonce
	// The SPHINCS+ verification ensures the signature is cryptographically valid
	// The timestamp and nonce ensure the signature is fresh and unique
	// Alice cannot reuse the signature, as the timestamp-nonce pair is unique and verified
	isValidSig = manager.VerifySignature(receivedMessage, receivedTimestamp, receivedNonce, sig, deserializedPK, merkleRoot)
	fmt.Printf("Charlie verifies signature valid: %v\n", isValidSig)

	// If both proof and signature are valid, Charlie accepts the message
	if isValidProof && isValidSig {
		// Print everything that Charlie loaded
		fmt.Printf("Charlie has received and loaded:\n")
		fmt.Printf("Alice's Public Key: %x\n", receivedPK)   // Print the public key in hex format
		fmt.Printf("Alice's Proof: %x\n", receivedProof)     // Print the proof in hex format
		fmt.Printf("Alice's Message: %s\n", receivedMessage) // Print the received message
		fmt.Printf("Alice's Timestamp: %x (%d)\n", receivedTimestamp, receivedTimestampInt)
		fmt.Printf("Alice's Nonce: %x\n", receivedNonce)
		fmt.Printf("Alice's RootHash: %x\n", receivedMerkleRootHash) // Print the Merkle root hash

		// Print total size in bytes
		totalSize := len(receivedPK) + len(receivedProof) + len(receivedMessage) + len(receivedTimestamp) + len(receivedNonce) + len(receivedMerkleRootHash)
		fmt.Printf("Total Size in Bytes: %d\n", totalSize) // Output the total size
	} else {
		// Do not print anything when the proof or signature is invalid
		fmt.Println("Invalid proof or signature.")
	}

	// Charlie stores the timestamp-nonce pair in LevelDB for future reuse detection
	// This ensures Alice cannot reuse the signature later, as Charlie will check for duplicates
	err = db.Put(append(receivedTimestamp, receivedNonce...), []byte("seen"), nil)
	if err != nil {
		log.Fatal("Failed to store timestamp-nonce pair:", err)
	}
}
