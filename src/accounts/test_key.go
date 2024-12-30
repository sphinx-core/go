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
	passphrase, base32Passkey, hashedPasskey, fingerprint, err := seed.GenerateKeys()
	if err != nil {
		log.Fatalf("Error generating keys: %v", err)
	}

	fmt.Println("Passphrase: ", passphrase)
	fmt.Println("Passkey: ", base32Passkey)
	fmt.Printf("HashedPasskey: %x\n", hashedPasskey)
	fmt.Printf("Fingerprint: %x\n", fingerprint)

	// Verify the passkey
	isValid, rootHash, derivedHashedPasskey, err := utils.VerifyBase32Passkey(base32Passkey)
	if err != nil {
		fmt.Printf("Verification failed: %v\n", err)
	} else {
		fmt.Printf("Verification result: %t\nRootHash of FingerPrint: %x\nDerivedHashedPasskey: %x\n", isValid, rootHash, derivedHashedPasskey)
	}
}
