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

package wots

import "fmt"

// Defines the NewKeyManager function that initializes a KeyManager and returns a pointer to it and an error
func NewKeyManager() (*KeyManager, error) {
	// Initializes WOTS parameters by calling NewWOTSParams for w=16
	params := NewWOTSParams()
	// Generates a private-public key pair using the initialized parameters
	sk, pk, err := GenerateKeyPair(params)
	// Checks if there was an error during key pair generation
	if err != nil {
		// Returns nil and a formatted error if key pair generation failed
		return nil, fmt.Errorf("failed to generate initial key pair: %v", err)
	}
	// Returns a pointer to a new KeyManager struct with initialized fields
	return &KeyManager{
		// Assigns the WOTS parameters to the KeyManager
		Params: params,
		// Assigns the generated private key as the current private key
		CurrentSK: sk,
		// Assigns the generated public key as the current public key
		CurrentPK: pk,
		// Sets the next public key to nil, as no next key exists at initialization
		NextPK: nil,
	}, nil
}

// Defines the SignAndRotate method on KeyManager, which signs a message and rotates keys, returning a signature, current public key, next public key, and error
func (km *KeyManager) SignAndRotate(message []byte) (*Signature, *PublicKey, *PublicKey, error) {
	// Signs the message using the current private key
	sig, err := km.CurrentSK.Sign(message)
	// Checks if there was an error during signing
	if err != nil {
		// Returns nil for all return values and a formatted error if signing failed
		return nil, nil, nil, fmt.Errorf("failed to sign message: %v", err)
	}

	// Stores the current public key for return, to be used for signature verification
	currentPK := km.CurrentPK

	// Generates a new private-public key pair using the KeyManager's parameters
	newSK, newPK, err := GenerateKeyPair(km.Params)
	// Checks if there was an error during new key pair generation
	if err != nil {
		// Returns nil for all return values and a formatted error if key pair generation failed
		return nil, nil, nil, fmt.Errorf("failed to generate new key pair: %v", err)
	}

	// Updates the KeyManager's current private key with the new private key
	km.CurrentSK = newSK
	// Updates the KeyManager's current public key with the new public key
	km.CurrentPK = newPK
	// Stores the new public key as the next public key for future transaction verification
	km.NextPK = newPK

	// Returns the signature, current public key (for verification), new public key (for system registration), and nil error
	return sig, currentPK, newPK, nil
}
