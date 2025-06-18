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

// go/src/handshake/types.go
package security

import (
	"crypto/cipher"

	"github.com/prometheus/client_golang/prometheus"
)

// Message represents a secure P2P or RPC message.
// It consists of a message type and associated data payload.
type Message struct {
	Type string      `json:"type"` // Type of the message, such as "transaction", "block", "jsonrpc", etc.
	Data interface{} `json:"data"` // Generic data payload associated with the message
}

// Handshake manages TLS or secure channel handshakes,
// and tracks metrics related to the handshake process.
type Handshake struct {
	Metrics *HandshakeMetrics // Pointer to a structure that holds handshake-related metrics
}

// HandshakeMetrics encapsulates Prometheus metrics
// for tracking handshake latency and error statistics.
type HandshakeMetrics struct {
	Latency *prometheus.HistogramVec // HistogramVec to record handshake latency across different labels
	Errors  *prometheus.CounterVec   // CounterVec to count different types of handshake errors
}

// EncryptionKey holds the shared cryptographic material for secure communication.
// It wraps both the derived AES-GCM cipher and the original shared secret bytes.
type EncryptionKey struct {
	SharedSecret []byte      // The raw shared secret used to derive the AES key (usually from key exchange like X25519 or Kyber768)
	AESGCM       cipher.AEAD // AES-GCM instance used to perform authenticated encryption and decryption
}
