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
	"encoding/binary"
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
	EntropySize = 128 // Set default entropy size to 128 bits for 12-word mnemonic
	SaltSize    = 16  // 128 bits salt size
	PasskeySize = 32  // Set this to 32 bytes for a 256-bit output
	NonceSize   = 16  // 128 bits nonce size, adjustable as needed

	// Argon2 parameters
	memory      = 64 * 1024 // Memory cost set to 64 KiB (64 * 1024 bytes) for demonstration purpose
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
	entropy := make([]byte, EntropySize/8) // Ensure entropy is in byte units (EntropySize in bits)
	// Fill the slice with random bytes
	_, err := rand.Read(entropy)
	if err != nil {
		// Return an error if entropy generation fails
		return nil, fmt.Errorf("error generating entropy: %v", err)
	}

	// Check if the entropy size is valid
	if EntropySize != 128 && EntropySize != 160 && EntropySize != 192 && EntropySize != 224 && EntropySize != 256 {
		return nil, fmt.Errorf("invalid entropy size: %d, must be one of 128, 160, 192, 224, or 256 bits", EntropySize)
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
func GenerateKeys() (passphrase string, base32Passkey string, hashedPasskey []byte, fingerprint []byte, chainCode []byte, hmacKey []byte, err error) {
	// Step 1: Generate entropy for the mnemonic (passphrase generation).
	// We call GenerateEntropy to obtain random data that can be used as the basis for the passphrase.
	entropy, err := GenerateEntropy()
	if err != nil {
		// If there is an error during entropy generation, we return an empty result and the error.
		return "", "", nil, nil, nil, nil, fmt.Errorf("failed to generate entropy: %v", err)
	}

	// Step 2: Derive the passphrase from the entropy.
	// Using the entropy generated in Step 1, we generate the passphrase using the GeneratePassphrase function.
	passphrase, err = GeneratePassphrase(entropy)
	if err != nil {
		// If there is an error during passphrase generation, return an empty result and the error.
		return "", "", nil, nil, nil, nil, fmt.Errorf("failed to generate passphrase: %v", err)
	}

	// Step 3: Generate the passkey from the passphrase.
	// The passphrase is used to derive a passkey (usually through some hashing or key derivation process).
	passkey, err := GeneratePasskey(passphrase, nil)
	if err != nil {
		// If there is an error during passkey generation, return an empty result and the error.
		return "", "", nil, nil, nil, nil, fmt.Errorf("failed to generate passkey: %v", err)
	}

	// Step 4: Hash the passkey using SHA3-512.
	// The passkey is hashed using SHA3-512 to create a fixed-size hash value.
	hashedPasskey, err = HashPasskey(passkey)
	if err != nil {
		// If there is an error during hashing, return an empty result and the error.
		return "", "", nil, nil, nil, nil, fmt.Errorf("failed to hash passkey: %v", err)
	}

	// Truncate the hashed passkey to 256 bits (32 bytes).
	// We take the first 32 bytes of the SHA3-512 hash to use in further steps.
	selectedParts := hashedPasskey[:32]

	// Step 6: Generate a nonce (16 bytes).
	// A nonce is a random value used only once, typically to prevent replay attacks. Here, we generate it using `rand.Read`.
	nonce := make([]byte, 16)
	_, err = rand.Read(nonce)
	if err != nil {
		// If there is an error generating the nonce, return an empty result and the error.
		return "", "", nil, nil, nil, nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Step 7: Combine the selected parts and the nonce using bytes.Join.
	// We join the selected 32-byte hash and the 16-byte nonce together to create a combined data set.
	combinedParts := bytes.Join([][]byte{selectedParts, nonce}, []byte{})

	// Step 8: Create salt by combining "Base32Passkey" with the selected parts of the hashed passkey.
	// We concatenate the string "Base32Passkey" with the first 32 bytes of the hashed passkey to create a salt.
	salt := "Base32Passkey" + string(hashedPasskey[:32])
	saltBytes := []byte(salt)

	// Step 9: Apply Sponge Construction (SHA-3) for every 8-byte group over multiple iterations.
	reducedParts := make([]byte, 0) // Initialize an empty slice to hold the reduced data after operations.
	iterations := 5                 // Define the number of iterations to perform operations across the data.

	// Initialize a state (e.g., SHA3-256) with a specific padding size.
	stateSize := 256 / 8             // SHA3-256 uses 256-bit state (32 bytes).
	state := make([]byte, stateSize) // The state used for SHA3 Sponge construction.

	for round := 0; round < iterations; round++ { // Iterate for the specified number of iterations.
		for i := 0; i+7 < len(combinedParts); i += 8 { // Loop through the combinedParts slice in 8-byte chunks.

			// Extract each byte of the current 8-byte group into separate variables (a, b, c, d, e, f, g, h).
			a := combinedParts[i]   // First byte of the group
			b := combinedParts[i+1] // Second byte of the group
			c := combinedParts[i+2] // Third byte of the group
			d := combinedParts[i+3] // Fourth byte of the group
			e := combinedParts[i+4] // Fifth byte of the group
			f := combinedParts[i+5] // Sixth byte of the group
			g := combinedParts[i+6] // Seventh byte of the group
			h := combinedParts[i+7] // Eighth byte of the group

			// Combine bytes into a single 64-bit value to feed into SHA-3
			dataBlock := make([]byte, 8)
			binary.BigEndian.PutUint64(dataBlock, uint64(a)^uint64(b)<<8^uint64(c)<<16^uint64(d)<<24^uint64(e)<<32^uint64(f)<<40^uint64(g)<<48^uint64(h)<<56)

			// Absorb the current data block into the sponge state
			hash := sha3.New256() // Using SHA3-256 (256-bit output, 512-bit state)
			hash.Write(state)     // Absorb the current state
			hash.Write(dataBlock) // Absorb the current data block
			state = hash.Sum(nil) // Update the state with the new hash output

			// Squeeze: Continue to extract bits after each round.
			// Adjust the number of bits to extract depending on how many bits you need.
			for i := 0; i < len(state); i++ {
				// Take bits from the state and XOR with the result to mix it.
				mixedResult := state[i] ^ saltBytes[i%len(saltBytes)] // Apply salt on the state.

				// Append the mixed result to the reducedParts slice.
				reducedParts = append(reducedParts, mixedResult) // Append mixedResult directly.
			}

			// Additional squeeze operation to ensure more entropy is squeezed from the state
			additionalBits := len(state) // This depends on how many bits you want to extract from each round.
			for i := 0; i < additionalBits; i++ {
				// Continue to squeeze bits from the state, adjusting as needed.
				reducedParts = append(reducedParts, state[i]) // Extract additional bits to the reducedParts.
			}

			// After completing the squeeze and extracting, mix again by XORing with salt for added randomness.
			for j := 0; j < len(saltBytes); j++ {
				reducedParts[len(reducedParts)-1] ^= saltBytes[j%len(saltBytes)] // XOR the result with the salt
			}
		}

		// After completing the inner loop, update combinedParts to the reducedParts.
		combinedParts = reducedParts
	}

	// Now, trim the result to the desired output length
	outputLength := 8 // Define the length of the output here (can be dynamic as needed).
	if len(combinedParts) > outputLength {
		combinedParts = combinedParts[:outputLength] // Trim to the desired length
	}

	// Step 10: Encode the reduced parts in Base32.
	base32Encoded := EncodeBase32(combinedParts)

	// Step 11: Generate a fingerprint using the hashed passkey and reduced parts.
	fingerprint, chainCode, err = utils.GenerateRootHash(combinedParts, hashedPasskey)
	if err != nil {
		return "", "", nil, nil, nil, nil, fmt.Errorf("failed to generate fingerprint: %v", err)
	}

	// Step 12: GenerateHmacKey to generate the HMAC key (chain code) using passphrase and reduced parts.
	hmacKey, err = utils.GenerateHmacKey(passphrase, combinedParts)
	if err != nil {
		return "", "", nil, nil, nil, nil, fmt.Errorf("failed to generate HMAC key: %v", err)
	}

	// Return the generated passphrase, encoded passkey, hashed passkey, and fingerprint.
	return passphrase, base32Encoded, hashedPasskey, fingerprint, chainCode, hmacKey, nil
}
