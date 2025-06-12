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
	"log"
	"net"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	// handshakeLatency tracks the latency of Kyber768 handshakes using a Prometheus histogram.
	handshakeLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "kyber_handshake_latency_seconds", // Metric name
			Help:    "Latency of Kyber768 handshakes",  // Description of the metric
			Buckets: prometheus.DefBuckets,             // Default latency buckets for histogram
		},
		[]string{"protocol"}, // Label by protocol type (e.g., "p2p", "rpc")
	)

	// handshakeErrors counts total Kyber768 handshake failures using a Prometheus counter.
	handshakeErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kyber_handshake_errors_total",              // Metric name
			Help: "Total number of Kyber768 handshake errors", // Description of the metric
		},
		[]string{"protocol"}, // Label by protocol type
	)
)

// init registers the Prometheus metrics so they can be collected and exposed.
func init() {
	prometheus.MustRegister(handshakeLatency, handshakeErrors) // Register histogram and counter metrics
}

// NewHandshake initializes a new Handshake object with Prometheus metrics attached.
func NewHandshake() *Handshake {
	return &Handshake{
		Metrics: &HandshakeMetrics{ // Assign metrics to the handshake
			Latency: handshakeLatency, // Latency histogram
			Errors:  handshakeErrors,  // Error counter
		},
	}
}

// PerformHandshake executes a Kyber768 key exchange using the provided network connection.
func (h *Handshake) PerformHandshake(conn net.Conn, protocol string, isInitiator bool) (*EncryptionKey, error) {
	start := time.Now() // Record start time to measure latency

	// Execute Kyber768 key encapsulation mechanism (KEM); initiator defines key generation direction
	kem, err := PerformKEM(conn, isInitiator)
	if err != nil {
		// Increment the error counter with the protocol label if handshake fails
		h.Metrics.Errors.WithLabelValues(protocol).Inc()
		log.Printf("Kyber768 handshake error for %s: %v", protocol, err) // Log the error
		return nil, err                                                  // Return nil key and error
	}

	// Record and observe the handshake latency duration
	h.Metrics.Latency.WithLabelValues(protocol).Observe(time.Since(start).Seconds())

	// Log success message after successful key exchange
	log.Printf("Kyber768 handshake successful for %s", protocol)

	return kem, nil // Return the resulting encryption key
}
