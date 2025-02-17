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
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"log"

	seed "github.com/sphinx-core/go/src/accounts/phrase"
	key "github.com/sphinx-core/go/src/core/sphincs/key/backend"
	"github.com/sphinx-core/go/src/core/wallet/crypter"
	config "github.com/sphinx-core/go/src/core/wallet/utils"
)

func main() {
	// Initialize wallet config
	walletConfig, err := config.NewWalletConfig()
	if err != nil {
		log.Fatal("Failed to initialize wallet config:", err)
	}
	defer walletConfig.Close()

	// Initialize key manager
	keyManager, err := key.NewKeyManager()
	if err != nil {
		log.Fatal("Failed to initialize KeyManager:", err)
	}

	// Generate keys
	sk, pk, err := keyManager.GenerateKey()
	if err != nil {
		log.Fatal("Failed to generate keys:", err)
	}

	// Serialize secret key
	skBytes, err := sk.SerializeSK()
	if err != nil {
		log.Fatal("Failed to serialize SK:", err)
	}

	// Serialize public key
	pkBytes, err := pk.SerializePK()
	if err != nil {
		log.Fatal("Failed to serialize PK:", err)
	}

	// Generate passphrase and base32 passkey
	passphrase, base32Passkey, _, _, _, _, err := seed.GenerateKeys()
	if err != nil {
		log.Fatalf("Failed to generate keys from seed: %v", err)
	}

	fmt.Printf("Passphrase: %s\n", passphrase)
	fmt.Printf("Base32Passkey: %s\n", base32Passkey)

	// Decode Base32 passkey
	decodedBase32Passkey, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(base32Passkey)
	if err != nil {
		log.Fatalf("Base32 passkey decoding failed: %v", err)
	}

	// Ensure decodedBase32Passkey is exactly 16 bytes
	if len(decodedBase32Passkey) < crypter.WALLET_CRYPTO_IV_SIZE {
		hashed := sha256.Sum256(decodedBase32Passkey)
		decodedBase32Passkey = hashed[:crypter.WALLET_CRYPTO_IV_SIZE]
	}

	// Generate salt from passphrase + decoded passkey
	combined := append([]byte(passphrase), decodedBase32Passkey...)
	hash := sha256.Sum256(combined)
	salt := hash[:crypter.WALLET_CRYPTO_IV_SIZE] // First 16 bytes

	fmt.Printf("Derived Salt: %x\n", salt)

	// Initialize crypter
	crypt := &crypter.CCrypter{}

	// Set encryption key
	if !crypt.SetKeyFromPassphrase([]byte(passphrase), salt, 1000) {
		log.Fatalf("Failed to set key from passphrase and salt")
	}

	// Encrypt secret key
	encryptedSecretKey, err := crypt.Encrypt(skBytes)
	if err != nil {
		log.Fatalf("Failed to encrypt secret key: %v", err)
	}

	// Save encrypted secret key
	err = walletConfig.SaveKeyPair(encryptedSecretKey, pkBytes)
	if err != nil {
		log.Fatalf("Failed to save key pair to LevelDB: %v", err)
	}

	fmt.Printf("Stored Encrypted Secret Key: %x\n", encryptedSecretKey)

	// Load the encrypted key
	loadedSkBytes, _, err := walletConfig.LoadKeyPair()
	if err != nil {
		log.Fatalf("Failed to load key pair from LevelDB: %v", err)
	}

	fmt.Printf("Retrieved Encrypted Secret Key: %x\n", loadedSkBytes)

	decryptedSecretKey, err := crypt.Decrypt(loadedSkBytes)
	if err != nil {
		log.Fatalf("Failed to decrypt secret key: %v", err)
	}

	fmt.Printf("Decrypted Secret Key: %x\n", decryptedSecretKey)
}
