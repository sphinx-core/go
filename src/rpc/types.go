package rpc

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sphinx-core/go/src/core"
	"github.com/sphinx-core/go/src/security"
)

// Metrics holds RPC-related Prometheus metrics.
type Metrics struct {
	RequestCount   *prometheus.CounterVec
	RequestLatency *prometheus.HistogramVec
	ErrorCount     *prometheus.CounterVec
}

// Server processes JSON-RPC requests.
type Server struct {
	messageCh  chan *security.Message
	metrics    *Metrics
	blockchain *core.Blockchain
}
