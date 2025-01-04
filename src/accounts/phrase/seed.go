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

package seed

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"unicode/utf8"

	sips3 "github.com/sphinx-core/go/src/accounts/mnemonic"
	"github.com/sphinx-core/go/src/common"
	key "github.com/sphinx-core/go/src/core/sphincs/key/backend"
	utils "github.com/sphinx-core/go/src/core/wallet/utils"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/sha3"
)

// SIPS-0004 https://github.com/sphinx-core/sips/wiki/SIPS0004

// Define constants for the sizes used in the seed generation process
const (
	// EntropySize determines the length of entropy to be generated
	EntropySize = 16 // 128 bits for 12-word mnemonic
	SaltSize    = 16 // 128 bits salt size
	PasskeySize = 32 // Set this to 32 bytes for a 256-bit output
	NonceSize   = 16 // 128 bits nonce size, adjustable as needed

	// Argon2 parameters
	// Argon memory standard is required minimum 15MiB (15 * 1024 * 1024) memory in allocation
	memory      = 64 * 1024 // Memory cost set to 64 KiB (64 * 1024 bytes) is for demonstration purpose
	iterations  = 2         // Number of iterations for Argon2id set to 2
	parallelism = 1         // Degree of parallelism set to 1
	tagSize     = 32        // Tag size set to 256 bits (32 bytes)
)

// GenerateSalt generates a cryptographically secure random salt.
func GenerateSalt() ([]byte, error) {
	// Create a byte slice for the salt
	salt := make([]byte, SaltSize)
	// Fill the slice with random bytes
	_, err := rand.Read(salt)
	if err != nil {
		// Return an error if salt generation fails
		return nil, fmt.Errorf("error generating salt: %v", err)
	}
	// Return the generated salt
	return salt, nil
}

// GenerateNonce generates a cryptographically secure random nonce.
func GenerateNonce() ([]byte, error) {
	// Create a byte slice for the nonce
	nonce := make([]byte, NonceSize)
	// Fill the slice with random bytes
	_, err := rand.Read(nonce)
	if err != nil {
		// Return an error if nonce generation fails
		return nil, fmt.Errorf("error generating nonce: %v", err)
	}
	// Return the generated nonce
	return nonce, nil
}

// GenerateEntropy generates secure random entropy for private key generation.
func GenerateEntropy() ([]byte, error) {
	// Create a byte slice for entropy
	entropy := make([]byte, EntropySize)
	// Fill the slice with random bytes
	_, err := rand.Read(entropy)
	if err != nil {
		// Return an error if entropy generation fails
		return nil, fmt.Errorf("error generating entropy: %v", err)
	}
	// Return the raw entropy for sips3
	return entropy, nil
}

// GeneratePassphrase generates a sips0003 passphrase from entropy.
func GeneratePassphrase(entropy []byte) (string, error) {
	// The entropy length is used to determine the mnemonic length
	entropySize := len(entropy) * 8 // Convert bytes to bits

	// Create a new mnemonic (passphrase) from the provided entropy size
	passphrase, _, err := sips3.NewMnemonic(entropySize)
	if err != nil {
		return "", fmt.Errorf("error generating mnemonic: %v", err)
	}

	// Return the generated passphrase
	return passphrase, nil
}

// GeneratePasskey generates a passkey using Argon2 with the given passphrase and an optional public key as input material.
// If no public key (pk) is provided, a new one will be generated.
func GeneratePasskey(passphrase string, pk []byte) ([]byte, error) {
	// Step 1: Validate the passphrase encoding (UTF-8 validation).
	if !utf8.Valid([]byte(passphrase)) {
		return nil, errors.New("invalid UTF-8 encoding in passphrase")
	}

	// Step 2: Check if the public key (pk) is empty, and generate a new one if necessary.
	if len(pk) == 0 {
		// Initialize the KeyManager for key generation.
		keyManager, err := key.NewKeyManager()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize KeyManager: %v", err)
		}

		// Generate a new key pair.
		_, generatedPk, err := keyManager.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("failed to generate new public key: %v", err)
		}

		// Serialize the generated public key to bytes.
		pk, err = generatedPk.SerializePK()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize new public key: %v", err)
		}
	}

	// Step 3: Convert the passphrase to bytes for processing.
	passphraseBytes := []byte(passphrase)

	// Step 4: Perform double hashing on the public key using a custom Sphinx hash.
	firstHash := common.SpxHash(pk)                // First Sphinx hash of the public key.
	doubleHashedPk := common.SpxHash(firstHash[:]) // Double Sphinx hash of the public key.

	// Step 5: Combine the passphrase and double-hashed public key as input key material (IKM).
	ikmHashInput := bytes.Join([][]byte{passphraseBytes, doubleHashedPk[:]}, []byte{}) // Concatenate passphraseBytes and doubleHashedPk[:]
	ikm := sha256.Sum256(ikmHashInput)                                                 // Derive the initial key material using SHA-256.

	// Step 6: Create a salt string using the double-hashed public key and passphrase.
	salt := "passphrase" + string(doubleHashedPk)

	// Step 7: Convert the salt string to bytes.
	saltBytes := []byte(salt)

	// Step 8: Generate a random nonce to enhance the salt uniqueness.
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, fmt.Errorf("error generating nonce: %v", err)
	}

	// Step 9: Combine the salt and nonce for the final Argon2 salt.
	combinedSaltAndNonce := bytes.Join([][]byte{saltBytes, nonce}, []byte{})

	// Step 10: Use Argon2 to derive the passkey using the IKM and the combined salt.
	passkey := argon2.IDKey(ikm[:], combinedSaltAndNonce, iterations, memory, parallelism, PasskeySize)

	// Return the derived passkey.
	return passkey, nil
}

// HashPasskey hashes the given passkey using SHA3-512 (Keccak-512).
func HashPasskey(passkey []byte) ([]byte, error) {
	// Initialize the SHA3-512 hasher.
	hash := sha3.NewLegacyKeccak512()

	// Write the passkey to the hasher.
	if _, err := hash.Write(passkey); err != nil {
		return nil, fmt.Errorf("error hashing with SHA3-512: %v", err)
	}

	// Return the final hash as bytes.
	return hash.Sum(nil), nil
}

// EncodeBase32 encodes the input data into Base32 format without padding.
func EncodeBase32(data []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
}

// GenerateKeys generates a passphrase, a hashed Base32-encoded passkey, and its fingerprint.
func GenerateKeys() (passphrase string, base32Passkey string, hashedPasskey []byte, fingerprint []byte, err error) {
	// Step 1: Generate entropy for the mnemonic (passphrase generation).
	entropy, err := GenerateEntropy()
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("failed to generate entropy: %v", err)
	}

	// Step 2: Derive the passphrase from the entropy.
	passphrase, err = GeneratePassphrase(entropy)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("failed to generate passphrase: %v", err)
	}

	// Step 3: Generate the passkey from the passphrase.
	passkey, err := GeneratePasskey(passphrase, nil)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("failed to generate passkey: %v", err)
	}

	// Step 4: Hash the passkey using SHA3-512.
	hashedPasskey, err = HashPasskey(passkey)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("failed to hash passkey: %v", err)
	}

	// Apply XOR for every 4-byte group to reduce the size to 128-bits (16 bytes)
	selectedParts := make([]byte, 0) // Create a new slice to store the XOR results

	// Process the hashed passkey in 4-byte chunks.
	for i := 0; i+3 < len(hashedPasskey); i += 4 { // Process each 4-byte group
		a := hashedPasskey[i]   // First byte of the group
		b := hashedPasskey[i+1] // Second byte of the group
		c := hashedPasskey[i+2] // Third byte of the group
		d := hashedPasskey[i+3] // Fourth byte of the group

		// XOR the bytes in the group to reduce the size.
		xorResult := a ^ b ^ c ^ d

		// Add the XOR result to the selectedParts slice using bytes.Join
		selectedParts = bytes.Join([][]byte{selectedParts, {xorResult}}, []byte{})
	}

	// Print Selected Parts (Raw)
	fmt.Printf("Selected Parts (Raw): %x\n", selectedParts)

	// Step 6: Generate a nonce (12 bytes).
	nonce := make([]byte, 12)
	_, err = rand.Read(nonce)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Print Nonce (Raw)
	fmt.Printf("Nonce (Raw): %x\n", nonce)

	// Step 7: Combine the selected parts and the nonce using bytes.Join.
	combinedParts := bytes.Join([][]byte{selectedParts, nonce}, []byte{})

	// Print Combined Parts (Raw)
	fmt.Printf("Combined Parts (Raw): %x\n", combinedParts)

	// Step 8: Apply XOR for every 8-byte group over multiple iterations.
	reducedParts := make([]byte, 0)
	iterations := 5000

	for round := 0; round < iterations; round++ {
		for i := 0; i+7 < len(combinedParts); i += 4 { // Process each 8-byte group.
			a := combinedParts[i]
			b := combinedParts[i+1]
			c := combinedParts[i+2]
			d := combinedParts[i+3]

			// XOR all bytes in the 8-byte group.
			xorResult := a ^ b ^ c ^ d

			// Append the XOR result to the reducedParts slice using bytes.Join.
			reducedParts = bytes.Join([][]byte{reducedParts, {xorResult}}, []byte{})
		}

		// After completing one round, update combinedParts with the reduced result.
		combinedParts = reducedParts
	}

	// Print Reduced Combined Parts (XOR Result after 5000 iterations)
	fmt.Printf("Reduced Combined Parts (XOR Result after 5000 iterations): %x\n", reducedParts)

	// Step 9: Encode the reduced parts in Base32.
	base32Encoded := EncodeBase32(combinedParts)

	// Step 10: Generate a fingerprint using the hashed passkey and reduced parts.
	fingerprint, err = utils.GenerateRootHash(combinedParts, hashedPasskey)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("failed to generate fingerprint: %v", err)
	}

	// Return the generated passphrase, encoded passkey, hashed passkey, and fingerprint.
	return passphrase, base32Encoded, hashedPasskey, fingerprint, nil
}
