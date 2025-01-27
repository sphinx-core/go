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
	// Initialize a wallet config for saving/loading keys
	walletConfig, err := utils.NewWalletConfig() // Initialize the wallet configuration with LevelDB
	if err != nil {
		log.Fatal("Failed to initialize wallet config:", err) // Log and exit if initialization fails
	}
	defer walletConfig.Close() // Ensure the database is closed when done

	// Step 1: Initialize the MultisigManager with a quorum value (e.g., 3 participants)
	quorum := 3
	manager, err := multisig.NewMultiSig(quorum)
	if err != nil {
		log.Fatalf("Error initializing MultisigManager: %v", err)
	}

	// Step 2: Generate key pairs for participants
	privateKeys := make([][]byte, 0, quorum) // Initialize slices with a capacity equal to the quorum
	publicKeys := make([][]byte, 0, quorum)
	for i := 0; i < quorum; i++ {
		sk, pk, err := manager.GenerateKeyPair()
		if err != nil {
			log.Fatalf("Error generating key pair for participant %d: %v", i, err)
		}
		// Append keys and reassign the result (necessary for Go's slice semantics)
		privateKeys = append(privateKeys, sk)
		publicKeys = append(publicKeys, pk)
		manager.Keys[i] = pk // Add the public key to the manager
	}

	// Step 3: Sign a message using each participant's private key
	message := []byte("This is a test message.")
	for i := 0; i < quorum; i++ {
		partyID := fmt.Sprintf("Participant%d", i+1)
		sig, merkleRoot, err := manager.SignMessage(message, privateKeys[i], partyID)
		if err != nil {
			log.Fatalf("Error signing message for %s: %v", partyID, err)
		}
		fmt.Printf("%s signed the message. Signature: %x, Merkle Root: %x\n", partyID, sig, merkleRoot)
	}

	// Step 4: Verify the collected signatures
	isValid, err := manager.VerifySignatures(message)
	if err != nil {
		log.Fatalf("Error verifying signatures: %v", err)
	}
	if isValid {
		fmt.Println("All signatures are valid, and quorum has been met.")
	} else {
		fmt.Println("Signatures are not valid, or quorum has not been met.")
	}

	// Step 5: Test proof validation for a participant
	partyID := "Participant1"
	isValidProof, err := manager.ValidateProof(partyID, message)
	if err != nil {
		log.Fatalf("Error validating proof for %s: %v", partyID, err)
	}
	if isValidProof {
		fmt.Printf("Proof for %s is valid.\n", partyID)
	} else {
		fmt.Printf("Proof for %s is invalid.\n", partyID)
	}

	// Step 6: Test wallet recovery using the required participants
	requiredParticipants := []string{"Participant1", "Participant2", "Participant3"}
	recoveryProof, err := manager.RecoveryKey(message, requiredParticipants)
	if err != nil {
		log.Fatalf("Error recovering wallet: %v", err)
	}
	fmt.Printf("Wallet recovery successful. Recovery Proof: %x\n", recoveryProof)
}
