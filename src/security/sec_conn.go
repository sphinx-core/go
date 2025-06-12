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

// NewEncryptionKey creates an AES-GCM cipher from a shared secret.
func NewEncryptionKey(sharedSecret []byte) (*EncryptionKey, error) {
	if len(sharedSecret) < 32 {
		return nil, errors.New("shared secret too short for AES-256")
	}
	block, err := aes.NewCipher(sharedSecret[:32])
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	log.Printf("Derived encryption key with shared secret: %s", hex.EncodeToString(sharedSecret[:16]))
	return &EncryptionKey{
		SharedSecret: sharedSecret,
		AESGCM:       aesGCM,
	}, nil
}

// Encrypt encrypts a message using AES-GCM.
func (enc *EncryptionKey) Encrypt(plaintext []byte) ([]byte, error) {
	if enc == nil || enc.AESGCM == nil {
		return nil, errors.New("encryption key is nil")
	}
	nonce := make([]byte, enc.AESGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := enc.AESGCM.Seal(nil, nonce, plaintext, nil)
	log.Printf("Encrypted message, nonce: %s, ciphertext length: %d", hex.EncodeToString(nonce), len(ciphertext))
	return append(nonce, ciphertext...), nil
}

// Decrypt decrypts a message using AES-GCM.
func (enc *EncryptionKey) Decrypt(ciphertext []byte) ([]byte, error) {
	if enc == nil || enc.AESGCM == nil {
		return nil, errors.New("encryption key is nil")
	}
	if len(ciphertext) < enc.AESGCM.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce := ciphertext[:enc.AESGCM.NonceSize()]
	encrypted := ciphertext[enc.AESGCM.NonceSize():]
	log.Printf("Decrypting message, nonce: %s, ciphertext length: %d", hex.EncodeToString(nonce), len(encrypted))
	plaintext, err := enc.AESGCM.Open(nil, nonce, encrypted, nil)
	if err != nil {
		log.Printf("Decryption failed: %v", err)
		return nil, err
	}
	return plaintext, nil
}

// PerformKEM performs hybrid X25519 + Kyber768 key exchange.
func PerformKEM(conn net.Conn, isInitiator bool) (*EncryptionKey, error) {
	if conn == nil {
		return nil, errors.New("connection is nil")
	}

	// --------------------
	// X25519 Key Exchange
	// --------------------
	var xPriv [32]byte
	if _, err := rand.Read(xPriv[:]); err != nil {
		return nil, err
	}
	xPub, err := curve25519.X25519(xPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	var xShared []byte
	if isInitiator {
		if _, err := conn.Write(xPub); err != nil {
			return nil, err
		}
		peerPub := make([]byte, 32)
		if _, err := io.ReadFull(conn, peerPub); err != nil {
			return nil, err
		}
		xShared, err = curve25519.X25519(xPriv[:], peerPub)
		if err != nil {
			return nil, err
		}
	} else {
		peerPub := make([]byte, 32)
		if _, err := io.ReadFull(conn, peerPub); err != nil {
			return nil, err
		}
		if _, err := conn.Write(xPub); err != nil {
			return nil, err
		}
		xShared, err = curve25519.X25519(xPriv[:], peerPub)
		if err != nil {
			return nil, err
		}
	}
	log.Printf("X25519 shared: %s", hex.EncodeToString(xShared[:16]))

	// --------------------
	// Kyber768 KEM
	// --------------------
	scheme := kyber768.Scheme()
	var kemShared []byte

	if isInitiator {
		peerPubBytes := make([]byte, scheme.PublicKeySize())
		if _, err := io.ReadFull(conn, peerPubBytes); err != nil {
			return nil, err
		}
		peerPub, err := scheme.UnmarshalBinaryPublicKey(peerPubBytes)
		if err != nil {
			return nil, err
		}
		ct, shared, err := scheme.Encapsulate(peerPub)
		if err != nil {
			return nil, err
		}
		kemShared = shared
		if _, err := conn.Write(ct); err != nil {
			return nil, err
		}
	} else {
		pub, priv, err := scheme.GenerateKeyPair()
		if err != nil {
			return nil, err
		}
		pubBytes, err := pub.MarshalBinary()
		if err != nil {
			return nil, err
		}
		if _, err := conn.Write(pubBytes); err != nil {
			return nil, err
		}
		ct := make([]byte, scheme.CiphertextSize())
		if _, err := io.ReadFull(conn, ct); err != nil {
			return nil, err
		}
		shared, err := scheme.Decapsulate(priv, ct)
		if err != nil {
			return nil, err
		}
		kemShared = shared
	}
	log.Printf("Kyber768 shared: %s", hex.EncodeToString(kemShared[:16]))

	// Combine shared secrets
	combined := append(xShared, kemShared...)
	finalShared := sha512.Sum512(combined)

	return NewEncryptionKey(finalShared[:])
}

// SecureMessage serializes and encrypts a message.
func SecureMessage(msg *Message, enc *EncryptionKey) ([]byte, error) {
	if enc == nil {
		return nil, errors.New("encryption key is nil")
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	log.Printf("Encoding message, type: %s, data length: %d", msg.Type, len(data))
	return enc.Encrypt(data)
}

// DecodeSecureMessage decrypts and parses a message.
func DecodeSecureMessage(data []byte, enc *EncryptionKey) (*Message, error) {
	if enc == nil {
		return nil, errors.New("encryption key is nil")
	}
	log.Printf("Decoding message, data length: %d", len(data))
	plaintext, err := enc.Decrypt(data)
	if err != nil {
		return nil, err
	}
	log.Printf("Decrypted plaintext length: %d", len(plaintext))
	var msg Message
	if err := json.Unmarshal(plaintext, &msg); err != nil {
		return nil, err
	}
	if err := msg.ValidateMessage(); err != nil {
		return nil, err
	}
	return &msg, nil
}
