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
	key "github.com/sphinx-core/go/src/core/sphincs/key/backend"
	"github.com/sphinx-core/go/src/core/wallet/crypter"
	config "github.com/sphinx-core/go/src/core/wallet/utils"
)

func main() {
	// Initialize a wallet config for saving/loading keys
	walletConfig, err := config.NewWalletConfig() // Initialize the wallet configuration with LevelDB
	if err != nil {
		log.Fatal("Failed to initialize wallet config:", err) // Log and exit if initialization fails
	}
	defer walletConfig.Close() // Ensure the database is closed when done

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
	// Generate passphrase, base32 passkey, hashed passkey, and fingerprint from a seed
	passphrase, base32Passkey, hashedPasskey, FingerPrint, hmacKey, err := seed.GenerateKeys()
	if err != nil {
		log.Fatalf("Failed to generate keys from seed: %v", err) // Log and exit if key generation from seed fails
	}

	// Print the generated keys for reference
	fmt.Printf("Passphrase: %s\n", passphrase)
	fmt.Printf("Base32Passkey: %s\n", base32Passkey)
	fmt.Printf("Hashed Passkey (hex): %x\n", hashedPasskey)
	fmt.Printf("Fingerprint: %s\n", FingerPrint) // Use the FingerPrint variable
	fmt.Printf("Fingerprint: %s\n", hmacKey)     // Use the FingerPrint variable

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
	separator := []byte("|") // Define a custom separator
	combinedData := append(append(encryptedSecretKey, separator...), encryptedHashedPasskey...)

	// Save the combined encrypted data using the walletConfig (from config package)
	err = walletConfig.SaveKeyPair(combinedData, pkBytes) // Save the combined data using the config package
	if err != nil {
		log.Fatalf("Failed to save key pair to LevelDB: %v", err)
	}

	// Load the combined data from LevelDB for later decryption
	loadedSkBytes, loadedPkBytes, err := walletConfig.LoadKeyPair() // Load the key pair from LevelDB
	if err != nil {
		log.Fatalf("Failed to load key pair from LevelDB: %v", err)
	}

	// Decrypt the loaded data using passphrase and base32 passkey for key regeneration
	// Regenerate the decryption key from passphrase and base32 passkey
	// Set the decryption key using the passphrase and base32 passkey
	if !crypt.SetKeyFromPassphrase(hashedPasskey, salt, 1000) {
		log.Fatalf("Failed to set key for decryption from passphrase and base32 passkey") // Log and exit if key setting fails
	}

	// Decrypt the secret key
	decryptedSecretKey, err := crypt.Decrypt(loadedSkBytes)
	if err != nil {
		log.Fatalf("Failed to decrypt secret key: %v", err) // Log and exit if decryption fails
	}
	fmt.Printf("Decrypted Secret Key: %x\n", decryptedSecretKey) // Print the decrypted secret key in hexadecimal format

	// Decrypt the hashed passkey
	decryptedHashedPasskey, err := crypt.Decrypt(loadedPkBytes)
	if err != nil {
		log.Fatalf("Failed to decrypt hashed passkey: %v", err) // Log and exit if decryption fails
	}
	fmt.Printf("Decrypted Hashed Passkey: %x\n", decryptedHashedPasskey) // Print the decrypted hashed passkey
}
