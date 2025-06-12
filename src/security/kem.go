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

// go/src/security/kem.go
package security

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"golang.org/x/crypto/curve25519"
)

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
