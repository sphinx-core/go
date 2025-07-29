// MIT License
//
// # Copyright (c) 2024 sphinx-core
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

// go/src/handshake/aes.go
package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
)

// NewEncryptionKey creates a new AES-GCM encryption key from a shared secret
func NewEncryptionKey(sharedSecret []byte) (*EncryptionKey, error) {
	// Ensure the shared secret is long enough for AES-256 (32 bytes)
	if len(sharedSecret) < 32 {
		return nil, errors.New("shared secret too short for AES-256")
	}

	// Create AES block cipher with the first 32 bytes of the shared secret
	block, err := aes.NewCipher(sharedSecret[:32])
	if err != nil {
		return nil, err
	}

	// Wrap the AES block cipher in a GCM (Galois/Counter Mode) for authenticated encryption
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Log derived encryption key (only first 16 bytes shown for debugging)
	log.Printf("Derived encryption key with shared secret: %s", hex.EncodeToString(sharedSecret[:16]))

	// Return a new EncryptionKey object
	return &EncryptionKey{
		SharedSecret: sharedSecret,
		AESGCM:       aesGCM,
	}, nil
}

// Encrypt encrypts the given plaintext using AES-GCM
func (enc *EncryptionKey) Encrypt(plaintext []byte) ([]byte, error) {
	// Ensure encryption key is properly initialized
	if enc == nil || enc.AESGCM == nil {
		return nil, errors.New("encryption key is nil")
	}

	// Generate a random nonce of appropriate size
	nonce := make([]byte, enc.AESGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Encrypt the plaintext using AES-GCM and append the nonce
	ciphertext := enc.AESGCM.Seal(nil, nonce, plaintext, nil)

	// Log the encryption event
	log.Printf("Encrypted message, nonce: %s, ciphertext length: %d", hex.EncodeToString(nonce), len(ciphertext))

	// Return the combined nonce and ciphertext
	return append(nonce, ciphertext...), nil
}

// Decrypt decrypts the given ciphertext using AES-GCM
func (enc *EncryptionKey) Decrypt(ciphertext []byte) ([]byte, error) {
	// Check for valid encryption key
	if enc == nil || enc.AESGCM == nil {
		return nil, errors.New("encryption key is nil")
	}

	// Ensure ciphertext includes a nonce
	if len(ciphertext) < enc.AESGCM.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	// Extract the nonce and the actual ciphertext
	nonce := ciphertext[:enc.AESGCM.NonceSize()]
	encrypted := ciphertext[enc.AESGCM.NonceSize():]

	// Log the decryption attempt
	log.Printf("Decrypting message, nonce: %s, ciphertext length: %d", hex.EncodeToString(nonce), len(encrypted))

	// Decrypt the message using AES-GCM
	plaintext, err := enc.AESGCM.Open(nil, nonce, encrypted, nil)
	if err != nil {
		log.Printf("Decryption failed: %v", err)
		return nil, err
	}
	return plaintext, nil
}

// SecureMessage serializes and encrypts the message struct
func SecureMessage(msg *Message, enc *EncryptionKey) ([]byte, error) {
	// Encode the message to JSON
	data, err := msg.Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode message: %v", err)
	}
	log.Printf("Encoding message, type: %s, data length: %d", msg.Type, len(data))

	// Encrypt the data using the EncryptionKey
	ciphertext, err := enc.Encrypt(data)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt message: %v", err)
	}
	log.Printf("Encrypted message, nonce: %x, ciphertext length: %d", ciphertext[:enc.AESGCM.NonceSize()], len(ciphertext))
	return ciphertext, nil
}

// DecodeSecureMessage decrypts and deserializes an encrypted message
func DecodeSecureMessage(data []byte, enc *EncryptionKey) (*Message, error) {
	// Check encryption key
	if enc == nil {
		return nil, errors.New("encryption key is nil")
	}

	// Log input size
	log.Printf("Decoding message, data length: %d", len(data))

	// Decrypt message
	plaintext, err := enc.Decrypt(data)
	if err != nil {
		return nil, err
	}

	// Log plaintext size
	log.Printf("Decrypted plaintext length: %d", len(plaintext))

	// Parse plaintext JSON into Message struct
	var msg Message
	if err := json.Unmarshal(plaintext, &msg); err != nil {
		return nil, err
	}

	// Validate the message contents
	if err := msg.ValidateMessage(); err != nil {
		return nil, err
	}

	// Return parsed message
	return &msg, nil
}
