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
	walletConfig, err := utils.NewWalletConfig()
	if err != nil {
		log.Fatal("Failed to initialize wallet config:", err)
	}
	defer walletConfig.Close()

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
		sig, merkleRoot, err := manager.SignMessage(message, privKeys[i], partyID)
		if err != nil {
			log.Fatalf("Error signing message for %s: %v", partyID, err)
		}
		fmt.Printf("%s signed the message. Signature: %x, Merkle Root: %x\n", partyID, sig, merkleRoot)

		err = manager.AddSig(i, sig)
		if err != nil {
			log.Fatalf("Error adding signature: %v", err)
		}
	}

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
	pubKey := manager.GetStoredPK()[0] // Use public key here
	sig := []byte("signature data here")
	err = manager.AddSigFromPubKey(pubKey, sig)
	if err != nil {
		log.Fatalf("Error adding signature from pubKey: %v", err)
	}
}
