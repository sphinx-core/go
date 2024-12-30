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

// Example of Login Flow
// Here's a simplified approach to a login process:

// During Registration:
// Generate a random salt and nonce.
// Use the passphrase to generate the passkey.
// Store the salt, nonce, and Base32-encoded truncated passkey.

// During Login:
// Retrieve the stored salt and nonce.
// Use the entered passphrase, stored salt, and nonce to regenerate the passkey.
// Truncate the regenerated hash (if you decide to keep truncation).
// Compare the truncated hash to the stored truncated hash.

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
// If no public key is provided, a new one will be generated.
func GeneratePasskey(passphrase string, pk []byte) ([]byte, error) {
	// Step 1: Validate the passphrase encoding (UTF-8 validation)
	if !utf8.Valid([]byte(passphrase)) {
		return nil, errors.New("invalid UTF-8 encoding in passphrase")
	}

	// Step 2: Check if pk is empty, and generate a new one if necessary.
	if len(pk) == 0 {
		keyManager, err := key.NewKeyManager() // Initialize the KeyManager
		if err != nil {
			return nil, fmt.Errorf("failed to initialize KeyManager: %v", err)
		}

		_, generatedPk, err := keyManager.GenerateKey() // Generate a new key pair
		if err != nil {
			return nil, fmt.Errorf("failed to generate new public key: %v", err)
		}

		pk, err = generatedPk.SerializePK() // Serialize the generated public key to bytes
		if err != nil {
			return nil, fmt.Errorf("failed to serialize new public key: %v", err)
		}
	}

	// Step 3: Convert the passphrase to bytes
	passphraseBytes := []byte(passphrase)

	// Step 4: Perform double sphinx hash hashing on the public key
	firstHash := common.SpxHash(pk)                // First sphinx hash of the public key
	doubleHashedPk := common.SpxHash(firstHash[:]) // Second sphinx hash (double hash) of the public key

	// Step 5: Combine passphrase and double-hashed public key for key material
	ikmHashInput := append(passphraseBytes, doubleHashedPk[:]...)
	ikm := sha256.Sum256(ikmHashInput) // Using SHA-256 to derive initial key material (IKM)

	// Step 6: Generate salt by combining the hashed public key and passphrase
	salt := "passphrase" + string(doubleHashedPk)

	// Step 7: Convert salt to bytes
	saltBytes := []byte(salt)

	// Step 8: Generate a random nonce
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, fmt.Errorf("error generating nonce: %v", err)
	}

	// Step 9: Combine the salt and nonce to create a unique salt for Argon2
	combinedSaltandNonce := append(saltBytes, nonce...)

	// Step 10: Derive the passkey using Argon2 with IKM and combined salt
	passkey := argon2.IDKey(ikm[:], combinedSaltandNonce, iterations, memory, parallelism, PasskeySize)
	return passkey, nil
}

func HashPasskey(passkey []byte) ([]byte, error) {
	// Use SHA3-512 (Keccak-512) to hash the passkey
	hash := sha3.NewLegacyKeccak512() // Create the Keccak-512 hasher
	if _, err := hash.Write(passkey); err != nil {
		return nil, fmt.Errorf("error hashing with SHA3-512: %v", err)
	}

	// Return the final hashed output
	return hash.Sum(nil), nil
}

// EncodeBase32 encodes the data in Base32 without padding.
func EncodeBase32(data []byte) string {
	// Encode the data in Base32 format without any padding
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
}

// GenerateKeys generates a passphrase and a hashed, Base32-encoded passkey.
func GenerateKeys() (passphrase string, base32Passkey string, hashedPasskey []byte, FingerPrint []byte, err error) {
	// Generate entropy for the mnemonic
	entropy, err := GenerateEntropy()
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("failed to generate entropy: %v", err)
	}

	// Generate passphrase from entropy
	passphrase, err = GeneratePassphrase(entropy)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("failed to generate passphrase: %v", err)
	}

	// Generate passkey from the passphrase
	passkey, err := GeneratePasskey(passphrase, nil)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("failed to generate passkey: %v", err)
	}

	// Hash the generated passkey
	hashedPasskey, err = HashPasskey(passkey)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("failed to hash passkey: %v", err)
	}

	// Ensure hashedPasskey is long enough
	hashLen := len(hashedPasskey)
	if hashLen < 6 {
		return "", "", nil, nil, fmt.Errorf("hashed passkey is too short to truncate")
	}

	// Randomly select 2-byte segments from the hash without overlap
	selectedParts := make([][]byte, 3)    // To store the 3 selected parts
	selectedIndices := make(map[int]bool) // To track used indices and prevent overlap

	for i := 0; i < 3; i++ {
		var start int
		for {
			// Randomly select a start index ensuring space for 2 bytes
			startIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(hashLen-2))) // Ensure space for 2 bytes
			start = int(startIndex.Int64())

			// Ensure the selected segment does not overlap with previously selected segments
			if !selectedIndices[start] && !selectedIndices[start+1] {
				// Mark the indices as used
				selectedIndices[start] = true
				selectedIndices[start+1] = true
				break
			}
		}

		// Extract the 2-byte segment starting from the random index
		selectedParts[i] = hashedPasskey[start : start+2]
	}

	// Combine the selected parts
	combinedParts := append(selectedParts[0], selectedParts[1]...)
	combinedParts = append(combinedParts, selectedParts[2]...)

	// Encode the combinedParts (6 bytes) in Base32
	base32Passkey = EncodeBase32(combinedParts)

	// Generate root hash of combined parts and hashed passkey
	FingerPrint, err = utils.GenerateRootHash(combinedParts, hashedPasskey)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("failed to generate root hash: %v", err)
	}

	// Print the raw FingerPrint length (in bytes) and its hex representation
	fmt.Printf("RootHash (roothash of combined part and hashedPasskey, 256-bit): %x\n", FingerPrint)

	// Return the generated passphrase, Base32-encoded passkey, and hashed passkey
	return passphrase, base32Passkey, hashedPasskey, FingerPrint, nil
}
