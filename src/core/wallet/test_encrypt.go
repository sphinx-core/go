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
	"bytes"
	"fmt"
	"log"
	"os"

	seed "github.com/sphinx-core/sphinx-core/src/accounts/phrase"
	key "github.com/sphinx-core/sphinx-core/src/core/sphincs/key/backend"
	"github.com/sphinx-core/sphinx-core/src/core/wallet/crypter"
	"github.com/syndtr/goleveldb/leveldb"
)

// saveToFile saves the provided data to a specified file path.
func saveToFile(filepath string, data []byte) error {
	// Create or open the file for writing
	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %v", filepath, err) // Return an error if file creation fails
	}
	defer file.Close() // Ensure the file is closed once the function finishes

	// Write data to the file
	_, err = file.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write data to file %s: %v", filepath, err) // Return an error if writing fails
	}
	return nil // Return nil if the operation is successful
}

// loadFromFile reads the data from the specified file.
func loadFromFile(filepath string) ([]byte, error) {
	// Read the content of the file
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %v", filepath, err) // Return an error if reading fails
	}
	return data, nil // Return the data if the operation is successful
}

func main() {
	// Define the keystore directory path
	keystoreDir := "src/accounts/keystore"

	// Create the keystore directory if it doesn't already exist
	err := os.MkdirAll(keystoreDir, os.ModePerm)
	if err != nil {
		log.Fatal("Failed to create keystore directory:", err) // Log and exit if directory creation fails
	}

	// Open the LevelDB database for storing keys
	db, err := leveldb.OpenFile(keystoreDir+"/sphinxkeys", nil)
	if err != nil {
		log.Fatal("Failed to open LevelDB:", err) // Log and exit if database opening fails
	}
	defer db.Close() // Ensure the database is closed once the function finishes

	// Initialize a key manager for generating keys
	keyManager, err := key.NewKeyManager()
	if err != nil {
		log.Fatal("Failed to initialize KeyManager:", err) // Log and exit if key manager initialization fails
	}

	// Generate secret key (SK) and public key (PK) using the key manager
	sk, pk, err := keyManager.GenerateKey()
	if err != nil {
		log.Fatal("Failed to generate keys:", err) // Log and exit if key generation fails
	}

	// Serialize the secret key into bytes for storage or display
	skBytes, err := sk.SerializeSK()
	if err != nil {
		log.Fatal("Failed to serialize SK:", err) // Log and exit if serialization fails
	}
	fmt.Printf("Secret Key (SK): %x\n", skBytes)                    // Print the secret key in hexadecimal format
	fmt.Printf("Size of Secret Key (SK): %d bytes\n", len(skBytes)) // Print the size of the SK

	// Serialize the public key into bytes for storage or display
	pkBytes, err := pk.SerializePK()
	if err != nil {
		log.Fatal("Failed to serialize PK:", err) // Log and exit if serialization fails
	}
	fmt.Printf("Public Key (PK): %x\n", pkBytes)                    // Print the public key in hexadecimal format
	fmt.Printf("Size of Public Key (PK): %d bytes\n", len(pkBytes)) // Print the size of the PK

	// Generate passphrase, base32 passkey, and hashed passkey from a seed
	passphrase, base32Passkey, hashedPasskey, err := seed.GenerateKeys()
	if err != nil {
		log.Fatalf("Failed to generate keys from seed: %v", err) // Log and exit if key generation from seed fails
	}
	// Print the generated keys for reference
	fmt.Printf("Passphrase: %s\n", passphrase)
	fmt.Printf("Base32Passkey: %s\n", base32Passkey)
	fmt.Printf("Hashed Passkey (hex): %x\n", hashedPasskey)

	// Initialize crypter for encryption/decryption
	crypt := &crypter.CCrypter{}
	// Generate random salt for encryption
	salt, err := crypter.GenerateRandomBytes(crypter.WALLET_CRYPTO_IV_SIZE)
	if err != nil {
		log.Fatalf("Failed to generate salt: %v", err) // Log and exit if salt generation fails
	}

	// Set the encryption key using the hashed passkey and salt
	if !crypt.SetKeyFromPassphrase(hashedPasskey, salt, 1000) {
		log.Fatalf("Failed to set key from hashed passkey") // Log and exit if key setting fails
	}

	// Encrypt the secret key with the generated key
	encryptedSecretKey, err := crypt.Encrypt(skBytes)
	if err != nil {
		log.Fatalf("Failed to encrypt secret key: %v", err) // Log and exit if encryption fails
	}
	fmt.Printf("Encrypted Secret Key: %x\n", encryptedSecretKey) // Print the encrypted secret key in hexadecimal format

	// Encrypt the hashed passkey with the generated key
	encryptedHashedPasskey, err := crypt.Encrypt(hashedPasskey)
	if err != nil {
		log.Fatalf("Failed to encrypt hashed passkey: %v", err) // Log and exit if encryption fails
	}
	fmt.Printf("Encrypted Hashed Passkey: %x\n", encryptedHashedPasskey) // Print the encrypted hashed passkey

	// Combine both encrypted secret key and encrypted hashed passkey into a single data buffer
	separator := []byte(":::")                                                                  // Define a custom separator
	combinedData := append(append(encryptedSecretKey, separator...), encryptedHashedPasskey...) // Append both parts with separator

	// Save the combined encrypted data to a file
	err = saveToFile(keystoreDir+"/secretkey.dat", combinedData)
	if err != nil {
		log.Fatalf("Failed to save secret key to file: %v", err) // Log and exit if file saving fails
	}

	// Load the combined data from the file for later decryption
	loadedData, err := loadFromFile(keystoreDir + "/secretkey.dat")
	if err != nil {
		log.Fatalf("Failed to load data from file: %v", err) // Log and exit if file loading fails
	}

	// Split the combined data back into encrypted secret key and encrypted hashed passkey
	parts := bytes.Split(loadedData, separator)
	if len(parts) != 2 {
		log.Fatalf("Unexpected data format in src/accounts/keystore/secretkey.dat") // Log and exit if the data format is incorrect
	}
	loadedEncryptedSecretKey := parts[0]     // First part is the encrypted secret key
	loadedEncryptedHashedPasskey := parts[1] // Second part is the encrypted hashed passkey

	// Initialize crypter for decryption
	decryptCrypt := &crypter.CCrypter{}
	// Set the decryption key using the hashed passkey and salt
	if !decryptCrypt.SetKeyFromPassphrase(hashedPasskey, salt, 1000) {
		log.Fatalf("Failed to set key from hashed passkey for decryption") // Log and exit if key setting fails
	}

	// Decrypt the secret key
	decryptedSecretKey, err := decryptCrypt.Decrypt(loadedEncryptedSecretKey)
	if err != nil {
		log.Fatalf("Failed to decrypt secret key: %v", err) // Log and exit if decryption fails
	}
	fmt.Printf("Decrypted Secret Key: %x\n", decryptedSecretKey) // Print the decrypted secret key in hexadecimal format

	// Decrypt the hashed passkey
	decryptedHashedPasskey, err := decryptCrypt.Decrypt(loadedEncryptedHashedPasskey)
	if err != nil {
		log.Fatalf("Failed to decrypt hashed passkey: %v", err) // Log and exit if decryption fails
	}
	fmt.Printf("Decrypted Hashed Passkey: %x\n", decryptedHashedPasskey) // Print the decrypted hashed passkey
}
