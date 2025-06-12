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

// go/src/security/sec_conn.go
package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"golang.org/x/crypto/curve25519"
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

// PerformKEM performs hybrid key exchange: X25519 + Kyber768
func PerformKEM(conn net.Conn, isInitiator bool) (*EncryptionKey, error) {
	if conn == nil {
		return nil, errors.New("connection is nil")
	}

	// ----------- X25519 Key Exchange -----------
	var xPriv [32]byte // Generate a 32-byte private key
	if _, err := rand.Read(xPriv[:]); err != nil {
		return nil, err
	}

	// Generate public key from private key
	xPub, err := curve25519.X25519(xPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	var xShared []byte
	if isInitiator {
		// Send own public key first
		if _, err := conn.Write(xPub); err != nil {
			return nil, err
		}

		// Receive peer's public key
		peerPub := make([]byte, 32)
		if _, err := io.ReadFull(conn, peerPub); err != nil {
			return nil, err
		}

		// Compute shared secret using peer's public key
		xShared, err = curve25519.X25519(xPriv[:], peerPub)
		if err != nil {
			return nil, err
		}
	} else {
		// Receive peer's public key first
		peerPub := make([]byte, 32)
		if _, err := io.ReadFull(conn, peerPub); err != nil {
			return nil, err
		}

		// Send own public key after
		if _, err := conn.Write(xPub); err != nil {
			return nil, err
		}

		// Compute shared secret
		xShared, err = curve25519.X25519(xPriv[:], peerPub)
		if err != nil {
			return nil, err
		}
	}

	// Log the derived X25519 shared secret (first 16 bytes shown)
	log.Printf("X25519 shared: %s", hex.EncodeToString(xShared[:16]))

	// ----------- Kyber768 Post-Quantum KEM -----------
	scheme := kyber768.Scheme() // Use Kyber768 from CIRCL
	var kemShared []byte        // Will hold the KEM shared secret

	if isInitiator {
		// Receive peer's Kyber public key
		peerPubBytes := make([]byte, scheme.PublicKeySize())
		if _, err := io.ReadFull(conn, peerPubBytes); err != nil {
			return nil, err
		}

		// Unmarshal to CIRCL PublicKey
		peerPub, err := scheme.UnmarshalBinaryPublicKey(peerPubBytes)
		if err != nil {
			return nil, err
		}

		// Perform encapsulation and send ciphertext
		ct, shared, err := scheme.Encapsulate(peerPub)
		if err != nil {
			return nil, err
		}
		kemShared = shared
		if _, err := conn.Write(ct); err != nil {
			return nil, err
		}
	} else {
		// Generate Kyber public/private key pair
		pub, priv, err := scheme.GenerateKeyPair()
		if err != nil {
			return nil, err
		}

		// Marshal public key to bytes and send it
		pubBytes, err := pub.MarshalBinary()
		if err != nil {
			return nil, err
		}
		if _, err := conn.Write(pubBytes); err != nil {
			return nil, err
		}

		// Receive encapsulated ciphertext from peer
		ct := make([]byte, scheme.CiphertextSize())
		if _, err := io.ReadFull(conn, ct); err != nil {
			return nil, err
		}

		// Decapsulate to get the shared secret
		shared, err := scheme.Decapsulate(priv, ct)
		if err != nil {
			return nil, err
		}
		kemShared = shared
	}

	// Log the Kyber768 shared secret (first 16 bytes shown)
	log.Printf("Kyber768 shared: %s", hex.EncodeToString(kemShared[:16]))

	// ----------- Combine X25519 and Kyber Shared Secrets -----------
	combined := append(xShared, kemShared...) // Concatenate both secrets
	finalShared := sha512.Sum512(combined)    // Hash to get uniform length
	return NewEncryptionKey(finalShared[:])   // Return AES-GCM key from hashed result
}

// SecureMessage serializes and encrypts the message struct
func SecureMessage(msg *Message, enc *EncryptionKey) ([]byte, error) {
	// Check encryption key
	if enc == nil {
		return nil, errors.New("encryption key is nil")
	}

	// Serialize message to JSON
	data, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	// Log encoding info
	log.Printf("Encoding message, type: %s, data length: %d", msg.Type, len(data))

	// Encrypt the serialized data
	return enc.Encrypt(data)
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
