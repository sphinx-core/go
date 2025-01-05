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

	seed "github.com/sphinx-core/go/src/accounts/phrase"
	utils "github.com/sphinx-core/go/src/core/wallet/utils"
)

func main() {
	// Step 1: Generate the keys (passphrase, Base32-encoded passkey, hashed passkey, and fingerprint)
	// `GenerateKeys` is expected to return:
	// - passphrase: The original mnemonic phrase or seed phrase.
	// - base32Passkey: The passkey encoded in Base32 for storage or transmission.
	// - hashedPasskey: A hash derived from the passkey for verification purposes.
	// - fingerprint: A unique identifier derived from the hashed passkey.
	passphrase, base32Passkey, hashedPasskey, fingerprint, err := seed.GenerateKeys()
	if err != nil {
		// Log the error and terminate the program if key generation fails
		log.Fatalf("Error generating keys: %v", err)
	}

	// Step 2: Display the generated keys for debugging or information purposes
	fmt.Println("Passphrase: ", passphrase)          // Display the original mnemonic phrase
	fmt.Println("Passkey: ", base32Passkey)          // Display the Base32-encoded passkey
	fmt.Printf("HashedPasskey: %x\n", hashedPasskey) // Display the hashed passkey in hexadecimal format
	fmt.Printf("Fingerprint: %x\n", fingerprint)     // Display the fingerprint in hexadecimal format

	// Step 3: Verify the Base32 passkey
	// The `VerifyBase32Passkey` function decodes the Base32-encoded passkey, derives the hashed passkey and root hash,
	// and checks if the root hash matches the expected fingerprint or derived values.
	isValid, rootHash, derivedFingerprint, err := utils.VerifyBase32Passkey(base32Passkey)
	if err != nil {
		// If verification fails, print an error message
		fmt.Printf("Verification failed: %v\n", err)
	} else {
		// If verification succeeds, display the results
		fmt.Printf("Verification result: %t\n", isValid)           // Indicate whether the passkey is valid
		fmt.Printf("RootHash of Fingerprint: %x\n", rootHash)      // Display the computed root hash
		fmt.Printf("DerivedFingerprint: %x\n", derivedFingerprint) // Display the derived fingerprint
	}
}
