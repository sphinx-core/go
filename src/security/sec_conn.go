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
	"encoding/json"
	"errors"
	"net"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

// Kyber768Scheme is the KEM scheme for key exchange.
var Kyber768Scheme kem.Scheme = kyber768.Scheme()

// EncryptionKey manages the shared secret and AES-GCM cipher.
type EncryptionKey struct {
	SharedSecret []byte
	AESGCM       cipher.AEAD
}

// NewEncryptionKey derives an AES-GCM cipher from a shared secret.
func NewEncryptionKey(sharedSecret []byte) (*EncryptionKey, error) {
	block, err := aes.NewCipher(sharedSecret[:32]) // Use first 32 bytes for AES-256
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &EncryptionKey{
		SharedSecret: sharedSecret,
		AESGCM:       aesGCM,
	}, nil
}

// Encrypt encrypts a message using AES-GCM.
func (ek *EncryptionKey) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, ek.AESGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := ek.AESGCM.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

// Decrypt decrypts a message using AES-GCM.
func (ek *EncryptionKey) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < ek.AESGCM.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce := ciphertext[:ek.AESGCM.NonceSize()]
	encrypted := ciphertext[ek.AESGCM.NonceSize():]
	return ek.AESGCM.Open(nil, nonce, encrypted, nil)
}

// PerformKyberKeyExchange initiates a Kyber768 key exchange.
func PerformKyberKeyExchange(conn net.Conn, isInitiator bool) (*EncryptionKey, error) {
	var err error

	if isInitiator {
		// Generate key pair and send public key
		pubKey, privKey, err := Kyber768Scheme.GenerateKeyPair()
		if err != nil {
			return nil, err
		}
		pubKeyBytes, err := pubKey.MarshalBinary()
		if err != nil {
			return nil, err
		}
		if _, err := conn.Write(pubKeyBytes); err != nil {
			return nil, err
		}

		// Receive encapsulated shared secret
		ciphertext := make([]byte, Kyber768Scheme.CiphertextSize())
		if _, err := conn.Read(ciphertext); err != nil {
			return nil, err
		}
		sharedSecret, err := Kyber768Scheme.Decapsulate(privKey, ciphertext)
		if err != nil {
			return nil, err
		}
		return NewEncryptionKey(sharedSecret)
	}

	// Responder
	pubKeyBytes := make([]byte, Kyber768Scheme.PublicKeySize())
	if _, err := conn.Read(pubKeyBytes); err != nil {
		return nil, err
	}
	pubKey, err := Kyber768Scheme.UnmarshalBinaryPublicKey(pubKeyBytes)
	if err != nil {
		return nil, err
	}

	sharedSecret, ciphertext, err := Kyber768Scheme.Encapsulate(pubKey)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(ciphertext); err != nil {
		return nil, err
	}
	return NewEncryptionKey(sharedSecret)
}

// SecureMessage encodes and encrypts a message.
func SecureMessage(msg *Message, ek *EncryptionKey) ([]byte, error) {
	data, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	return ek.Encrypt(data)
}

// DecodeSecureMessage decrypts and decodes a message.
func DecodeSecureMessage(data []byte, ek *EncryptionKey) (*Message, error) {
	plaintext, err := ek.Decrypt(data)
	if err != nil {
		return nil, err
	}
	var msg Message
	if err := json.Unmarshal(plaintext, &msg); err != nil {
		return nil, err
	}
	if err := msg.ValidateMessage(); err != nil {
		return nil, err
	}
	return &msg, nil
}
