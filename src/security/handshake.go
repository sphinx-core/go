// security/handshake.go
package security

import (
	"crypto/tls"
	"log"
	"net"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Handshake manages TLS handshakes with metrics.
type Handshake struct {
	Config  *tls.Config
	Metrics *HandshakeMetrics
}

// HandshakeMetrics holds Prometheus metrics for TLS handshakes.
type HandshakeMetrics struct {
	Latency *prometheus.HistogramVec
	Errors  *prometheus.CounterVec
}

// NewHandshake creates a new Handshake instance.
func NewHandshake(config *tls.Config) *Handshake {
	metrics := &HandshakeMetrics{
		Latency: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "tls_handshake_latency_seconds",
				Help:    "Latency of TLS handshakes",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"protocol"},
		),
		Errors: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "tls_handshake_errors_total",
				Help: "Total number of TLS handshake errors",
			},
			[]string{"protocol"},
		),
	}
	return &Handshake{
		Config:  config,
		Metrics: metrics,
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
		log.Printf("TLS handshake successful for %s using %s", protocol, tlsConn.ConnectionState().CipherSuite)
	}
	return nil
}
