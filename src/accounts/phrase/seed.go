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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"math/big"
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
	NonceSize   = 8  // 64 bits nonce size, adjustable as needed

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
	ikmHashInput := append(passphraseBytes, doubleHashedPk[:]...)
	ikm := sha256.Sum256(ikmHashInput) // Derive the initial key material using SHA-256.

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
	combinedSaltAndNonce := append(saltBytes, nonce...)

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

	// Step 5: Select **6 characters** from the hashed passkey.
	selectedParts := make([]byte, 3)      // Create an array to store the 6 selected characters (bytes)
	selectedIndices := make(map[int]bool) // A map to track the indices that have already been selected

	// Loop to select 6 unique indices (for 6 characters) from the hashed passkey
	for i := 0; i < 3; i++ {
		var index int // Variable to store the random index for the current selection

		for {
			// Randomly select an index within the range of the hashed passkey length.
			selectedIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(hashedPasskey))))
			index = int(selectedIndex.Int64()) // Convert the selected random number to an integer

			// Ensure no overlap with previously selected indices.
			if !selectedIndices[index] {
				selectedIndices[index] = true // Mark this index as selected
				break                         // Exit the loop once a unique index is found
			}
		}

		// Once a unique index is selected, retrieve the corresponding byte from the hashed passkey.
		selectedParts[i] = hashedPasskey[index]
	}

	// Print selected parts for debugging (6 characters only)
	fmt.Printf("Selected Parts (Raw): %x\n", selectedParts)

	// Step 6: Generate a nonce that also has **6 characters**.
	nonce := make([]byte, 3)
	_, err = rand.Read(nonce)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Print nonce for debugging
	fmt.Printf("Nonce (Raw): %x\n", nonce)

	// Step 7: Combine the selected 6 characters and the nonce (Total of 12 bytes).
	combinedParts := append(selectedParts, nonce...)

	// Print combined parts for debugging (should output 12 bytes)
	fmt.Printf("Combined Parts (Raw): %x\n", combinedParts)

	// Step 8: Encode the combined parts in Base32.
	base32Encoded := EncodeBase32(combinedParts)

	// Debugging: Print the Base32 encoded result
	fmt.Printf("Base32 Encoded: %s\n", base32Encoded)

	// Ensure the Base32 output is exactly 12 characters
	if len(base32Encoded) > 12 {
		base32Passkey = base32Encoded[:12] // Truncate to 12 characters
	} else {
		base32Passkey = base32Encoded // Use the full encoding if it's already 12 characters
	}

	// Step 9: Generate a fingerprint using the hashed passkey and combined parts.
	fingerprint, err = utils.GenerateRootHash(combinedParts, hashedPasskey)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("failed to generate fingerprint: %v", err)
	}

	// Return all generated components.
	return passphrase, base32Passkey, hashedPasskey, fingerprint, nil
}
