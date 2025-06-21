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

	multisig "github.com/sphinx-core/go/src/core/multisig/mps"
	"github.com/sphinx-core/go/src/core/wallet/utils"
)

func main() {
	// Initialize wallet configuration
	walletConfig, err := utils.NewWalletConfig()
	if err != nil {
		log.Fatal("Failed to initialize wallet config:", err)
	}
	defer walletConfig.Close()

	// Set quorum for multisignature (e.g., 3 participants required)
	quorum := 3
	manager, err := multisig.NewMultiSig(quorum)
	if err != nil {
		log.Fatalf("Error initializing MultisigManager: %v", err)
	}

	// Retrieve participant private keys from the MultisigManager
	privKeys := make([][]byte, quorum)
	for i := 0; i < quorum; i++ {
		privKeys[i] = manager.GetStoredSK()[i] // Get stored private keys
	}

	// Sign a message using each participant's private key
	message := []byte("This is a test message.")
	for i := 0; i < quorum; i++ {
		partyID := fmt.Sprintf("Participant%d", i+1)
		// SignMessage returns signature, Merkle root, timestamp, and nonce
		// Timestamp ensures signatures are temporally bound, preventing reuse of old signatures
		// Nonce ensures each signature is unique, even for identical messages
		sig, merkleRoot, timestamp, nonce, err := manager.SignMessage(message, privKeys[i], partyID)
		if err != nil {
			log.Fatalf("Error signing message for %s: %v", partyID, err)
		}
		fmt.Printf("%s signed the message. Signature: %x, Merkle Root: %x, Timestamp: %x, Nonce: %x\n", partyID, sig, merkleRoot, timestamp, nonce)

		// Add the signature, timestamp, nonce, and Merkle root to the multisig
		// Timestamp and nonce are checked for freshness and uniqueness to prevent reuse
		// Merkle root ensures signature integrity
		err = manager.AddSig(i, sig, timestamp, nonce, merkleRoot)
		if err != nil {
			log.Fatalf("Error adding signature for %s: %v", partyID, err)
		}
	}

	// Verify all signatures to ensure quorum is met
	// Verification checks timestamp freshness, nonce uniqueness, SPHINCS+ cryptographic validity,
	// and Merkle root integrity, preventing Alice from reusing signatures
	isValid, err := manager.VerifySignatures(message)
	if err != nil {
		log.Fatalf("Error verifying signatures: %v", err)
	}
	if isValid {
		fmt.Println("All signatures are valid, and quorum has been met.")
	} else {
		fmt.Println("Signatures are not valid, or quorum has not been met.")
	}

	// Example of using AddSigFromPubKey
	// Use the first participant's public key, signature, timestamp, nonce, and Merkle root
	pubKey := manager.GetStoredPK()[0]
	// For demonstration, reuse the first signature (in practice, generate a new valid signature)
	sig, merkleRoot, timestamp, nonce, err := manager.SignMessage(message, privKeys[0], "Participant1")
	if err != nil {
		log.Fatalf("Error signing message for AddSigFromPubKey: %v", err)
	}
	// AddSigFromPubKey includes timestamp and nonce checks to prevent reuse
	// Alice cannot lie about reusing a signature due to timestamp-nonce storage in LevelDB
	err = manager.AddSigFromPubKey(pubKey, sig, timestamp, nonce, merkleRoot)
	if err != nil {
		log.Fatalf("Error adding signature from pubKey: %v", err)
	}
	fmt.Println("Signature added successfully using AddSigFromPubKey.")
}
