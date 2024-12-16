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

package crypter

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"log"

	"github.com/holiman/uint256"
)

const (
	WALLET_CRYPTO_KEY_SIZE   = 32               // AES-256: 256-bit (32 bytes) key size
	WALLET_CRYPTO_IV_SIZE    = 16               // Size of IV: 16 bytes (fixed for AES)
	WALLET_CRYPTO_NONCE_SIZE = 12               // AES GCM: 12-byte nonce (used as IV)
	AES_BLOCKSIZE            = 16               // AES block size: 16 bytes (128 bits, fixed for AES)
	CSHA512OutputSize        = 64               // SHA-512 output size: 64 bytes
	AES_GCM_TAG_SIZE         = 16               // GCM authentication tag size: 16 bytes
	AES_GCM_OVERHEAD         = AES_GCM_TAG_SIZE // Overhead for GCM: size of the authentication tag
)

// MasterKey represents the structure of a master key,
// used in cryptographic operations for deriving encryption keys.
type MasterKey struct {
	// VchCryptedKey holds the encrypted version of the private key or master key.
	// "Vch" stands for "vector of characters" (or bytes) often used for byte slices in cryptographic contexts.
	VchCryptedKey []byte `json:"vchCryptedKey"`

	// VchSalt contains the salt used during key derivation to add randomness and strengthen security.
	// "Vch" again refers to a byte slice (vector of characters).
	VchSalt []byte `json:"vchSalt"`

	// NDerivationMethod specifies the method used for deriving keys (e.g., PBKDF2, scrypt).
	// "N" is a common notation for numeric values or counts.
	NDerivationMethod uint32 `json:"nDerivationMethod"`

	// NDeriveIterations defines how many iterations are applied during key derivation,
	// typically used to increase computational cost and security.
	NDeriveIterations uint32 `json:"nDeriveIterations"`

	// VchOtherDerivationParameters is an additional byte slice that holds any other parameters
	// required by the derivation method, if applicable.
	VchOtherDerivationParameters []byte `json:"vchOtherDerivationParameters"`
}

// CCrypter handles AES encryption and decryption with key and IV.
type CCrypter struct {
	vchKey  []byte
	vchIV   []byte
	fKeySet bool
}

// NewMasterKey creates a new instance of MasterKey with default values.
func NewMasterKey() *MasterKey {
	return &MasterKey{
		NDeriveIterations:            25000,    // Default iterations
		NDerivationMethod:            0,        // Default method (0 = EVP_sha512)
		VchOtherDerivationParameters: []byte{}, // Empty default
	}
}

// Serialize serializes the MasterKey into a byte slice.
func (mk *MasterKey) Serialize() ([]byte, error) {
	return json.Marshal(mk)
}

// Deserialize populates the MasterKey from a byte slice.
func (mk *MasterKey) Deserialize(data []byte) error {
	return json.Unmarshal(data, mk)
}

// Uint256 represents a 256-bit unsigned integer.
type Uint256 struct {
	uint256 *uint256.Int
}

// NewUint256 creates a new Uint256 from a byte slice.
func NewUint256(b []byte) *Uint256 {
	u := new(Uint256)
	u.uint256 = new(uint256.Int).SetBytes(b)
	return u
}

// ToBytes converts Uint256 to a byte slice.
func (u *Uint256) ToBytes() []byte {
	return u.uint256.Bytes()
}

// BytesToUint256 converts a byte slice to Uint256.
func BytesToUint256(b []byte) *Uint256 {
	u := new(Uint256)
	u.uint256 = new(uint256.Int).SetBytes(b)
	return u
}

// NewCrypter: Initializes a new CCrypter instance and sets the encryption key from the master key.
// It returns the initialized CCrypter instance or an error if the key could not be set.
func NewCrypter(masterKey []byte) (*CCrypter, error) {
	// Create a new instance of CCrypter.
	cKeyCrypter := &CCrypter{}

	// Set the encryption key using the provided masterKey.
	// The second parameter (nil) indicates that no salt is used in this example.
	if !cKeyCrypter.SetKey(masterKey, nil) {
		// If setting the key fails, return an error indicating the failure.
		return nil, errors.New("failed to set key")
	}

	// Return the initialized CCrypter instance.
	return cKeyCrypter, nil
}

// BytesToKeySHA512AES: Derives an encryption key and initialization vector (IV) from the provided key data and salt using SHA-512.
// The key derivation process is repeated 'count' times for key stretching.
func (c *CCrypter) BytesToKeySHA512AES(salt, keyData []byte, count int) ([]byte, []byte, error) {
	// Validate input parameters: count must be greater than 0, and both keyData and salt must not be nil.
	if count <= 0 || keyData == nil || salt == nil {
		return nil, nil, errors.New("invalid parameters")
	}

	// Initialize a new SHA-512 hash function.
	hash := sha512.New()

	// Create a buffer to store the output of the SHA-512 hashing.
	// CSHA512OutputSize is likely 64 bytes (512 bits), the output size of SHA-512.
	buf := make([]byte, CSHA512OutputSize)

	// First hash step: H0 = SHA-512(keyData + salt)
	// Concatenate keyData and salt, and hash the result.
	hash.Write(keyData) // Write keyData to the hash function.
	hash.Write(salt)    // Write salt to the hash function.

	// Copy the first hash output (H0) into the buffer.
	copy(buf, hash.Sum(nil))

	// Perform the remaining hash steps: Hn = SHA-512(Hn-1), repeated 'count' times.
	for i := 1; i < count; i++ {
		// Reset the hash state for the next round.
		hash.Reset()

		// Hash the previous output (buf) to generate the next output (Hn).
		hash.Write(buf)

		// Copy the new hash result back into the buffer.
		copy(buf, hash.Sum(nil))
	}

	// After completing 'count' hash steps, the buffer contains the final hash value.
	// Ensure the buffer is large enough to hold both the key and IV.
	if len(buf) < WALLET_CRYPTO_KEY_SIZE+WALLET_CRYPTO_IV_SIZE {
		return nil, nil, errors.New("buffer too small")
	}

	// Split the final hash buffer into the key and IV.
	key := buf[:WALLET_CRYPTO_KEY_SIZE]                                              // First 32 bytes for the key.
	iv := buf[WALLET_CRYPTO_KEY_SIZE : WALLET_CRYPTO_KEY_SIZE+WALLET_CRYPTO_IV_SIZE] // Next 16 bytes for the IV.

	// Zero out the buffer to cleanse sensitive data from memory.
	memoryCleanse(buf)

	// Return the derived key and IV.
	return key, iv, nil
}

// SetKeyFromPassphrase: Derives an encryption key and initialization vector (IV) from the provided passphrase (keyData) and salt.
// The number of rounds specifies how many times to apply the hash function to derive the key (key stretching).
func (c *CCrypter) SetKeyFromPassphrase(keyData, salt []byte, rounds uint) bool {
	// Check if the number of rounds is valid and if the salt length matches the expected IV size.
	if rounds < 1 || len(salt) != WALLET_CRYPTO_IV_SIZE {
		// Log an error if the rounds are less than 1 or if the salt size is incorrect.
		log.Printf("Invalid rounds or salt length: rounds=%d, salt length=%d", rounds, len(salt))
		return false // Return false to indicate the key setup failed.
	}

	// Derive the encryption key and IV using the provided passphrase (keyData) and salt.
	// This process will perform key stretching using the BytesToKeySHA512AES method, which applies SHA-512 multiple times.
	key, iv, err := c.BytesToKeySHA512AES(salt, keyData, int(rounds))

	// If there was an error during key derivation, log the error and return false.
	if err != nil {
		log.Printf("Error deriving key and IV: %v", err)
		return false
	}

	// Check if the lengths of the derived key and IV match the expected sizes.
	if len(key) != WALLET_CRYPTO_KEY_SIZE || len(iv) != WALLET_CRYPTO_IV_SIZE {
		// Log a message if the key or IV length does not match the expected sizes.
		log.Printf("Derived key or IV length mismatch: key length=%d, iv length=%d", len(key), len(iv))

		// Clean the memory for both the key and IV to ensure sensitive data is wiped from memory.
		memoryCleanse(key)
		memoryCleanse(iv)

		// Return false because the derived key or IV is of incorrect size.
		return false
	}

	// Store the derived key and IV in the CCrypter instance (c).
	c.vchKey = key
	c.vchIV = iv

	// Mark the key as set (fKeySet = true), indicating the encryption key has been successfully initialized.
	c.fKeySet = true

	// Return true to indicate the key was successfully derived and set.
	return true
}

// SetKey: Sets the encryption key and initialization vector (IV) directly in the CCrypter object.
func (c *CCrypter) SetKey(newKey, newIV []byte) bool {
	// Check if the provided key and IV match the expected sizes.
	if len(newKey) != WALLET_CRYPTO_KEY_SIZE || len(newIV) != WALLET_CRYPTO_IV_SIZE {
		return false // Return false if the key or IV size is invalid.
	}

	// Allocate memory for the key and IV in the CCrypter object.
	c.vchKey = make([]byte, WALLET_CRYPTO_KEY_SIZE)
	c.vchIV = make([]byte, WALLET_CRYPTO_IV_SIZE)

	// Copy the new key and IV into the internal fields of the CCrypter object.
	copy(c.vchKey, newKey)
	copy(c.vchIV, newIV)

	// Mark the key as set, indicating the CCrypter object is ready to encrypt/decrypt.
	c.fKeySet = true
	return true // Return true to indicate successful key setup.
}

// Encrypt: Encrypts the provided plaintext using AES-256-GCM.
func (c *CCrypter) Encrypt(plaintext []byte) ([]byte, error) {
	// Check if the key and IV have been set in the CCrypter object.
	if !c.fKeySet {
		return nil, errors.New("key not set") // Return an error if the key has not been set.
	}

	// Generate a new IV (nonce) for AES-GCM encryption. The IV size must match WALLET_CRYPTO_NONCE_SIZE.
	iv := make([]byte, WALLET_CRYPTO_NONCE_SIZE)
	if _, err := rand.Read(iv); err != nil {
		return nil, err // Return an error if random IV generation fails.
	}

	// Create a new AES cipher block using the previously set key (AES-256).
	block, err := aes.NewCipher(c.vchKey)
	if err != nil {
		return nil, err // Return an error if AES cipher creation fails.
	}

	// Create a GCM cipher mode instance (Galois/Counter Mode) for the AES cipher.
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err // Return an error if GCM mode creation fails.
	}

	// Encrypt the plaintext using GCM. Seal appends the ciphertext to the IV (gcm.Seal).
	ciphertext := gcm.Seal(nil, iv, plaintext, nil)

	// Prepend the IV (nonce) to the ciphertext so it can be used for decryption.
	result := append(iv, ciphertext...)

	// Return the result (IV + ciphertext) as the final encrypted output.
	return result, nil
}

// Decrypt: Decrypts the provided ciphertext using AES-256-GCM.
func (c *CCrypter) Decrypt(ciphertext []byte) ([]byte, error) {
	// Check if the key and IV have been set in the CCrypter object.
	if !c.fKeySet {
		return nil, errors.New("key not set") // Return an error if the key has not been set.
	}

	// Check if the ciphertext is large enough to contain both the nonce (IV) and the ciphertext.
	if len(ciphertext) < WALLET_CRYPTO_NONCE_SIZE+AES_GCM_TAG_SIZE {
		return nil, errors.New("ciphertext too short") // Return an error if the ciphertext is too short.
	}

	// Extract the IV (nonce) from the beginning of the ciphertext.
	iv := ciphertext[:WALLET_CRYPTO_NONCE_SIZE]
	ciphertext = ciphertext[WALLET_CRYPTO_NONCE_SIZE:] // The remaining part is the actual encrypted data.

	// Create a new AES cipher block using the previously set key (AES-256).
	block, err := aes.NewCipher(c.vchKey)
	if err != nil {
		return nil, err // Return an error if AES cipher creation fails.
	}

	// Create a GCM cipher mode instance (Galois/Counter Mode) for the AES cipher.
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err // Return an error if GCM mode creation fails.
	}

	// Decrypt the ciphertext using GCM. The IV is used here to decrypt the data.
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, err // Return an error if decryption fails.
	}

	// Return the decrypted plaintext.
	return plaintext, nil
}

// EncryptSecret: Encrypts the given plaintext using a master key and an IV (Uint256).
func EncryptSecret(masterKey []byte, plaintext []byte, iv *Uint256) ([]byte, error) {
	// Initialize the crypter struct, which handles AES encryption and decryption.
	cKeyCrypter := &CCrypter{}

	// Generate a random salt of size equal to WALLET_CRYPTO_IV_SIZE for key derivation.
	salt, err := GenerateRandomBytes(WALLET_CRYPTO_IV_SIZE) // Use IV size for salt.
	if err != nil {
		// Return an error if salt generation fails.
		return nil, err
	}

	// Set the encryption key using the masterKey and the derived salt.
	// 10000 rounds of key derivation are used here (as an example). This simulates a password-based key derivation function.
	if !cKeyCrypter.SetKeyFromPassphrase(masterKey, salt, 10000) {
		// Return an error if setting the key fails.
		return nil, errors.New("failed to set key")
	}

	// Encrypt the plaintext using the AES-256-GCM cipher.
	ciphertext, err := cKeyCrypter.Encrypt(plaintext)
	if err != nil {
		// Return an error if the encryption process fails.
		return nil, err
	}

	// Return the ciphertext as the result of the encryption process.
	return ciphertext, nil
}

// DecryptSecret: Decrypts the ciphertext using a master key and an IV (Uint256).
func DecryptSecret(masterKey []byte, ciphertext []byte, iv *Uint256) ([]byte, error) {
	// Initialize the crypter struct for handling AES decryption.
	cKeyCrypter := &CCrypter{}

	// Generate a random salt (must match the one used during encryption).
	salt, err := GenerateRandomBytes(WALLET_CRYPTO_IV_SIZE)
	if err != nil {
		// Return an error if salt generation fails.
		return nil, err
	}

	// Set the decryption key using the masterKey and the derived salt.
	// The same number of rounds (10000) used during encryption must be applied.
	if !cKeyCrypter.SetKeyFromPassphrase(masterKey, salt, 10000) {
		// Return an error if setting the key fails.
		return nil, errors.New("failed to set key")
	}

	// Decrypt the ciphertext using AES-256-GCM cipher.
	plaintext, err := cKeyCrypter.Decrypt(ciphertext)
	if err != nil {
		// Return an error if the decryption process fails.
		return nil, err
	}

	// Return the decrypted plaintext.
	return plaintext, nil
}

// DecryptKey: Decrypts a crypted secret using a master key and IV derived from the public key.
func DecryptKey(masterKey []byte, cryptedSecret []byte, pubKey []byte) ([]byte, error) {
	// Convert the public key (pubKey) to a Uint256 structure, which will be used as the IV during decryption.
	iv := BytesToUint256(pubKey)

	// Decrypt the crypted secret using the master key and the IV derived from the public key.
	secret, err := DecryptSecret(masterKey, cryptedSecret, iv)
	if err != nil {
		// Return an error if the decryption process fails.
		return nil, err
	}

	// Ensure that the decrypted secret is of the expected size (32 bytes).
	if len(secret) != 32 {
		// Return an error if the size doesn't match.
		return nil, errors.New("decrypted secret size mismatch")
	}

	// Verify that the decrypted secret corresponds to the provided public key.
	if !VerifyPubKey(secret, pubKey) {
		// Return an error if the verification fails (decrypted secret doesn't match the public key).
		return nil, errors.New("decrypted key mismatch with public key")
	}

	// Return the decrypted secret as the result.
	return secret, nil
}

// MemoryCleanse: Zero out sensitive data from memory
func memoryCleanse(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// VerifyPubKey: Dummy verification for now
func VerifyPubKey(secret, pubKey []byte) bool {
	// Assumes pubKey derived from secret
	return bytes.Equal(secret, pubKey)
}

// Modify GenerateRandomBytes to accept an appropriate size for IV and Key
func GenerateRandomBytes(size int) ([]byte, error) {
	if size <= 0 {
		return nil, errors.New("size must be greater than 0")
	}
	b := make([]byte, size)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
