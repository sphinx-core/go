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

package utils

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/syndtr/goleveldb/leveldb"
)

// This package imnplementation of SIPS0004 & SIPS0005
// https://github.com/sphinx-core/sips/wiki/SIPS0004
// https://github.com/sphinx-core/sips/wiki/SIPS0005

// WalletConfig handles the storage and retrieval of keys in the keystore directory.
type WalletConfig struct {
	db *leveldb.DB // LevelDB database instance for storing keys.
}

// Get database
func (config *WalletConfig) GetDB() *leveldb.DB {
	return config.db
}

// NewWalletConfig initializes a new WalletConfig with a LevelDB instance for key storage.
func NewWalletConfig() (*WalletConfig, error) {
	// Define the path to the LevelDB database and keystore directory
	keystoreDir := "src/accounts/keystore"

	// Create the keystore directory if it doesn't already exist
	err := os.MkdirAll(keystoreDir, os.ModePerm)
	if err != nil {
		log.Fatal("Failed to create keystore directory:", err) // Log and exit if directory creation fails
		return nil, fmt.Errorf("failed to create keystore directory: %v", err)
	}

	// Open the LevelDB database for storing keys
	db, err := leveldb.OpenFile(keystoreDir+"/sphinxkeys", nil)
	if err != nil {
		log.Fatal("Failed to open LevelDB:", err) // Log and exit if database opening fails
		return nil, fmt.Errorf("failed to open LevelDB: %v", err)
	}

	// Return the WalletConfig with the LevelDB instance
	return &WalletConfig{db: db}, nil
}

// SaveKeyPair saves the combined encrypted data in LevelDB and as a .dat file
func (config *WalletConfig) SaveKeyPair(combinedData []byte, pk []byte) error {
	if combinedData == nil || pk == nil {
		return errors.New("combined data or public key is nil")
	}

	// Use a separator to concatenate the encrypted secret key and public key
	separator := []byte("|")
	finalData := append(combinedData, separator...)
	finalData = append(finalData, pk...)

	key := []byte("sphinxKeys")

	// Save the combined data in LevelDB
	err := config.db.Put(key, finalData, nil)
	if err != nil {
		return fmt.Errorf("failed to save combined data in LevelDB: %v", err)
	}

	// Save the .dat file to the disk
	keystoreDir := "src/accounts/keystore"
	filePath := filepath.Join(keystoreDir, "sphinxkeys.dat")

	// Ensure directory exists
	err = os.MkdirAll(keystoreDir, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to create keystore directory %s: %v", keystoreDir, err)
	}

	err = os.WriteFile(filePath, finalData, 0644)
	if err != nil {
		return fmt.Errorf("failed to save combined data to file %s: %v", filePath, err)
	}

	return nil
}

// LoadKeyPair retrieves the combined data and splits it back into SK and PK.
func (config *WalletConfig) LoadKeyPair() ([]byte, []byte, error) {
	// Define the key used to retrieve the combined data
	key := []byte("sphinxKeys")

	// Retrieve the combined data from LevelDB
	combinedData, err := config.db.Get(key, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load combined data from LevelDB: %v", err)
	}

	fmt.Printf("Combined Data: %x\n", combinedData) // Debug print to check format

	// Find the separator and split the data back into secret key (sk) and hashed passkey
	separator := []byte("|")
	parts := bytes.Split(combinedData, separator)
	if len(parts) != 2 {
		return nil, nil, errors.New("invalid combined data format")
	}

	// The first part is the encrypted secret key
	sk := parts[0]

	// The second part is the encrypted hashed passkey
	pk := parts[1]

	return sk, pk, nil
}

// Close closes the LevelDB database when done.
func (config *WalletConfig) Close() {
	if err := config.db.Close(); err != nil {
		log.Fatal("Failed to close LevelDB:", err)
	}
}
