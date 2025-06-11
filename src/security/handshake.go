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

// go/src/security/handshake.go
package security

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	handshakeLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "tls_handshake_latency_seconds",
			Help:    "Latency of TLS handshakes",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"protocol"},
	)
	handshakeErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tls_handshake_errors_total",
			Help: "Total number of TLS handshake errors",
		},
		[]string{"protocol"},
	)
)

func init() {
	prometheus.MustRegister(handshakeLatency, handshakeErrors)
}

func NewHandshake(config *tls.Config) *Handshake {
	return &Handshake{
		Config: config,
		Metrics: &HandshakeMetrics{
			Latency: handshakeLatency,
			Errors:  handshakeErrors,
		},
	}
}

// cipherSuiteName converts a TLS cipher suite ID to a human-readable name.
func cipherSuiteName(id uint16) string {
	switch id {
	case tls.TLS_AES_128_GCM_SHA256:
		return "TLS_AES_128_GCM_SHA256"
	case tls.TLS_AES_256_GCM_SHA384:
		return "TLS_AES_256_GCM_SHA384"
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		return "TLS_CHACHA20_POLY1305_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:
		return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305"
	case tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:
		return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"
	default:
		return fmt.Sprintf("Unknown(0x%04x)", id)
	}
}

// PerformHandshake executes a TLS handshake on the given connection.
func (h *Handshake) PerformHandshake(conn net.Conn, protocol string) error {
	start := time.Now()
	if tlsConn, ok := conn.(*tls.Conn); ok {
		if err := tlsConn.Handshake(); err != nil {
			h.Metrics.Errors.WithLabelValues(protocol).Inc()
			log.Printf("TLS handshake error for %s: %v", protocol, err)
			return err
		}
		h.Metrics.Latency.WithLabelValues(protocol).Observe(time.Since(start).Seconds())
		log.Printf("TLS handshake successful for %s using %s", protocol, cipherSuiteName(tlsConn.ConnectionState().CipherSuite))
	}
	return nil
}
