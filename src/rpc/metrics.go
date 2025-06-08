// rpc/metrics.go
package rpc

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all RPC-related Prometheus metrics.
type Metrics struct {
	RequestCount   *prometheus.CounterVec
	RequestLatency *prometheus.HistogramVec
	ErrorCount     *prometheus.CounterVec
}

// NewMetrics initializes RPC metrics.
func NewMetrics() *Metrics {
	return &Metrics{
		RequestCount: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rpc_request_total",
				Help: "Total number of RPC requests processed",
			},
			[]string{"method"},
		),
		RequestLatency: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "rpc_request_latency_seconds",
				Help:    "Latency of RPC requests in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method"},
		),
		ErrorCount: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rpc_error_total",
				Help: "Total number of RPC errors",
			},
			[]string{"method"},
		),
	}
}
