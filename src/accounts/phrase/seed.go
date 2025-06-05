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

	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"

	sips3 "github.com/sphinx-core/go/src/accounts/mnemonic"
	"github.com/sphinx-core/go/src/common"
	key "github.com/sphinx-core/go/src/core/sphincs/key/backend"
	auth "github.com/sphinx-core/go/src/core/wallet/auth"
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
	// OWASP have published guidance on Argon2 at https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
	// At time of writing (Jan 2023), this says:
	// Argon2id should use one of the following configuration settings as a base minimum which includes the minimum memory size (m), the minimum number of iterations (t) and the degree of parallelism (p).
	// m=37 MiB, t=1, p=1
	// m=15 MiB, t=2, p=1
	// Both of these configuration settings are equivalent in the defense they provide. The only difference is a trade off between CPU and RAM usage.
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
	ikm := sha3.Sum256(ikmHashInput)                                                   // Derive the initial key material using SHA-256.

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

// HashPasskey hashes the given passkey using SHA3-512.
func HashPasskey(passkey []byte) ([]byte, error) {
	// Initialize the SHA3-512 hasher.
	hash := sha3.New512()

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
// It derives a 6–8 byte output cryptographically from a large intermediate state to ensure
// the output is protected by the state's entropy against brute-force attacks.
func GenerateKeys() (passphrase string, base32Passkey string, hashedPasskey []byte, macKey []byte, chainCode []byte, fingerprint []byte, err error) {
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

	// Step 5: Call 512-bit hashedPasskey as key combined material.
	// Assign the 64-byte hashed passkey to selectedParts for further processing.
	selectedParts := hashedPasskey

	// Step 6: Generate a nonce (16 bytes).
	// A nonce is a random value used only once, typically to prevent replay attacks. Here, we generate it using rand.Read.
	nonce := make([]byte, 16)
	_, err = rand.Read(nonce)
	if err != nil {
		// If there is an error generating the nonce, return an empty result and the error.
		return "", "", nil, nil, nil, nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Step 7: Combine the selected parts and the nonce using bytes.Join.
	// We join the selected 64-byte hash and the 16-byte nonce together to create a combined data set.
	combinedParts := bytes.Join([][]byte{selectedParts, nonce}, []byte{})

	// Step 8: Create salt by combining "Base32Passkey" with the selected parts of the hashed passkey.
	// We concatenate the string "Base32Passkey" with the first 64 bytes of the hashed passkey to create a salt.
	salt := "Base32Passkey" + string(hashedPasskey)
	saltBytes := []byte(salt)

	// Step 9: Apply Sponge Construction (SHA-3) for every 8-byte group over multiple iterations.
	// Initialize an empty slice to hold the transformed data after SHA-3 operations.
	transformedParts := make([]byte, 0)
	// Define the number of iterations to perform operations across the data (5 iterations).
	iterations := 5
	// Set the state size for SHA3-256 (32 bytes, as SHA3-256 outputs 256 bits).
	stateSize := 256 / 8
	// Initialize the state array for the SHA-3 sponge construction.
	state := make([]byte, stateSize)

	// Iterate for the specified number of iterations to build the intermediate state.
	for round := 0; round < iterations; round++ {
		// Loop through the combinedParts slice in 8-byte chunks.
		for i := 0; i+7 < len(combinedParts); i += 8 {
			// Extract each byte of the current 8-byte group into separate variables (a, b, c, d, e, f, g, h).
			a := combinedParts[i]
			b := combinedParts[i+1]
			c := combinedParts[i+2]
			d := combinedParts[i+3]
			e := combinedParts[i+4]
			f := combinedParts[i+5]
			g := combinedParts[i+6]
			h := combinedParts[i+7]

			// Combine bytes into a single 64-bit value to feed into SHA-3.
			// Create an 8-byte slice to hold the 64-bit value.
			dataBlock := make([]byte, 8)
			// Create a 64-bit value from the 8 bytes using bitwise operations.
			// Ensure constant-time construction to avoid leaking information via timing attacks.
			binary.BigEndian.PutUint64(
				dataBlock, // The destination where the 64-bit value will be stored.
				uint64(a)<<56| // Shift the byte 'a' 56 bits to the left (to occupy the highest 8 bits).
					uint64(b)<<48| // Shift the byte 'b' 48 bits to the left (to occupy the second highest 8 bits).
					uint64(c)<<40| // Shift the byte 'c' 40 bits to the left.
					uint64(d)<<32| // Shift the byte 'd' 32 bits to the left.
					uint64(e)<<24| // Shift the byte 'e' 24 bits to the left.
					uint64(f)<<16| // Shift the byte 'f' 16 bits to the left.
					uint64(g)<<8| // Shift the byte 'g' 8 bits to the left.
					uint64(h), // No shift required for byte 'h', it occupies the lowest 8 bits.
			)

			// Absorb the current data block into the sponge state.
			// Initialize a new SHA3-256 hash function for the chunk.
			hash := sha3.New256()
			// Absorb the current state into the hash function.
			hash.Write(state)
			// Absorb the saltBytes to mix the salt with the state.
			hash.Write(saltBytes)
			// Finalize the hash and update the state with the 32-byte output.
			state = hash.Sum(nil)

			// New mixing operation to enhance diffusion.
			// Iterate over each byte in the state and modify it using a combination of:
			// 1. Adding the corresponding byte from saltBytes (modulo to cycle if needed).
			// 2. XORing with a shifted version of the next byte in the state.
			for i := 0; i < len(state); i++ {
				// Ensure constant-time modification to mitigate timing attacks.
				state[i] = (state[i] + saltBytes[i%len(saltBytes)]) ^ (state[(i+1)%len(state)] << 1)
			}

			// Squeeze: Extract bits from the state after each round.
			// Iterate over the state bytes to produce mixed results.
			for i := 0; i < len(state); i++ {
				// XOR each state byte with a salt byte for additional mixing.
				// Ensure constant-time extraction to avoid timing leaks.
				mixedResult := state[i] ^ saltBytes[i%len(saltBytes)]
				// Append the mixed result to the transformedParts slice.
				transformedParts = append(transformedParts, mixedResult)
			}

			// Additional squeeze operation to extract more entropy.
			// Define the number of additional bits to extract (32 bytes).
			additionalBits := len(state)
			// Append state bytes directly to transformedParts.
			for i := 0; i < additionalBits; i++ {
				// Continue to squeeze bits from the state for increased entropy.
				transformedParts = append(transformedParts, state[i])
			}

			// Mix again by XORing the last byte with salt for added randomness.
			// Iterate over saltBytes to apply XOR operations.
			for j := 0; j < len(saltBytes); j++ {
				// Ensure constant-time mixing to avoid timing attacks.
				transformedParts[len(transformedParts)-1] ^= saltBytes[j%len(saltBytes)]
			}
		}
		// Update combinedParts to transformedParts for the next iteration.
		// This exponentially grows the intermediate state (~2,621,440 bytes after 5 iterations).
		combinedParts = transformedParts
	}

	// Step 10: Derive the output length (6 or 8 bytes) deterministically from transformedParts.
	// Initialize a new SHA3-256 hash function to compress the large intermediate state.
	hash := sha3.New256()
	// Write the transformedParts (intermediate state, ~2,621,440 bytes) to the hash function.
	hash.Write(transformedParts)
	// Include saltBytes to bind the digest to the salt, enhancing security.
	hash.Write(saltBytes)
	// Finalize the hash to obtain a 32-byte digest.
	digest := hash.Sum(nil) // 32 bytes

	// Determine the output length (6 or 8 bytes) using the first byte of the digest.
	// Use the least significant bit to choose between 6 and 8 bytes deterministically.
	outputLength := 6
	if digest[0]&1 == 1 { // Check if the first byte’s LSB is 1.
		outputLength = 8
	}

	// Step 11: Derive the final output deterministically from the digest.
	// Allocate a slice to hold the output (6 or 8 bytes).
	selectedParts = make([]byte, outputLength)
	// Copy the first 6 or 8 bytes of the digest to selectedParts.
	// This ensures the output is a cryptographic derivative of the intermediate state.
	copy(selectedParts, digest[:outputLength])

	// Step 12: Encode the selected parts in Base32.
	// Convert the 6–8 byte output to a Base32 string (no padding, ~10–16 characters).
	// This produces a user-friendly password for authentication.
	base32Encoded := EncodeBase32(selectedParts)
	// Update combinedParts with selectedParts for compatibility with downstream functions.
	combinedParts = selectedParts

	// Step 13: Generate a MacKey used for validating combinedParts (Base32passkey) during login sessions.
	// Derive a MAC key and chain code using combinedParts and hashedPasskey.
	macKey, chainCode, err = utils.GenerateMacKey(combinedParts, hashedPasskey)
	if err != nil {
		// Return an error if MacKey generation fails.
		return "", "", nil, nil, nil, nil, fmt.Errorf("failed to generate macKey: %v", err)
	}

	// Step 14: Generate a fingerprint (a chain of generated passphrase and combinedParts).
	// Create a chain code to link the passphrase and output for verification.
	fingerprint, err = auth.GenerateChainCode(passphrase, combinedParts)
	if err != nil {
		// Return an error if fingerprint generation fails.
		return "", "", nil, nil, nil, nil, fmt.Errorf("failed to generate fingerprint: %v", err)
	}

	// Return the generated passphrase, encoded passkey, hashed passkey, MAC key,
	// chain code, fingerprint, and nil error on success.
	return passphrase, base32Encoded, hashedPasskey, macKey, chainCode, fingerprint, nil
}
