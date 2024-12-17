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

package config

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
)

// WalletConfig handles the storage and retrieval of keys in the keystore directory.
type keyConfig struct {
	keystoreDir string // Directory to store keys.
}

// NewWalletConfig initializes a new WalletConfig with a specified keystore directory.
func NewWalletConfig(keystoreDir string) (*keyConfig, error) {
	// Ensure the keystore directory exists.
	if err := os.MkdirAll(keystoreDir, os.ModePerm); err != nil {
		return nil, errors.New("failed to create keystore directory: " + err.Error())
	}

	return &keyConfig{keystoreDir: keystoreDir}, nil
}

// SaveKeyPair saves a serialized SPHINCS secret (sk) and public (pk) key pair into a single file (sphinxKeys.dat).
func (config *keyConfig) SaveKeyPair(sk []byte, pk []byte) error {
	if sk == nil || pk == nil {
		return errors.New("secret or public key is nil")
	}

	// Combine the secret and public keys into one byte slice
	combinedKeys := append(sk, pk...)

	// Define the file path for saving both keys in one file
	keysPath := filepath.Join(config.keystoreDir, "sphinxKeys.dat")

	// Save the combined keys to the keystore directory
	err := ioutil.WriteFile(keysPath, combinedKeys, 0644)
	if err != nil {
		return errors.New("failed to save keys: " + err.Error())
	}

	return nil
}

// LoadKeyPair retrieves the serialized SPHINCS secret (sk) and public (pk) key pair from the sphinxKeys.dat file.
func (config *keyConfig) LoadKeyPair() ([]byte, []byte, error) {
	// Define the file path for the combined keys
	keysPath := filepath.Join(config.keystoreDir, "sphinxKeys.dat")

	// Retrieve the combined keys from the file
	combinedKeys, err := ioutil.ReadFile(keysPath)
	if err != nil {
		return nil, nil, errors.New("failed to load keys: " + err.Error())
	}

	// Check that the combined keys length matches the expected total length (96 bytes + 48 bytes)
	if len(combinedKeys) != 144 { // 96 bytes for SK + 48 bytes for PK
		return nil, nil, errors.New("invalid combined keys length")
	}

	// Split the keys back into separate secret key (sk) and public key (pk)
	sk := combinedKeys[:96] // First 96 bytes are for the secret key
	pk := combinedKeys[96:] // Last 48 bytes are for the public key

	return sk, pk, nil
}
