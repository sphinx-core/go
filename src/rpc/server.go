// rpc/server.go
package rpc

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/yourusername/myblockchain/core"
	"github.com/yourusername/myblockchain/security"
)

// Metrics holds RPC-related Prometheus metrics.
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

// Server processes JSON-RPC requests.
type Server struct {
	messageCh  chan *security.Message
	metrics    *Metrics
	blockchain *core.Blockchain
}

// NewServer creates a new RPC server.
func NewServer(messageCh chan *security.Message) *Server {
	metrics := NewMetrics()
	prometheus.MustRegister(metrics.RequestCount, metrics.RequestLatency, metrics.ErrorCount)
	return &Server{
		messageCh:  messageCh,
		metrics:    metrics,
		blockchain: core.NewBlockchain(),
	}
}

// HandleRequest processes a JSON-RPC request.
func (s *Server) HandleRequest(data []byte) ([]byte, error) {
	var req JSONRPCRequest
	if err := json.Unmarshal(data, &req); err != nil {
		s.metrics.ErrorCount.WithLabelValues("unknown").Inc()
		return nil, err
	}

	start := time.Now()
	s.metrics.RequestCount.WithLabelValues(req.Method).Inc()
	defer s.metrics.RequestLatency.WithLabelValues(req.Method).Observe(time.Since(start).Seconds())

	resp := JSONRPCResponse{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "add_transaction":
		var tx core.Transaction
		if err := json.Unmarshal([]byte(req.Params.(string)), &tx); err != nil {
			s.metrics.ErrorCount.WithLabelValues(req.Method).Inc()
			return nil, err
		}
		if err := s.blockchain.AddTransaction(tx); err != nil {
			s.metrics.ErrorCount.WithLabelValues(req.Method).Inc()
			return nil, err
		}
		s.messageCh <- &security.Message{Type: "transaction", Data: tx}
		resp.Result = map[string]string{"status": "Transaction received"}
	case "getblockcount":
		resp.Result = s.blockchain.GetBlockCount()
	case "getbestblockhash":
		resp.Result = fmt.Sprintf("%x", s.blockchain.GetBestBlockHash())
	case "getblock":
		var hash string
		if err := json.Unmarshal([]byte(req.Params.(string)), &hash); err != nil {
			s.metrics.ErrorCount.WithLabelValues(req.Method).Inc()
			return nil, err
		}
		hashBytes, err := hex.DecodeString(hash)
		if err != nil {
			s.metrics.ErrorCount.WithLabelValues(req.Method).Inc()
			return nil, err
		}
		block, err := s.blockchain.GetBlockByHash(hashBytes)
		if err != nil {
			s.metrics.ErrorCount.WithLabelValues(req.Method).Inc()
			return nil, err
		}
		resp.Result = block
	case "getblocks":
		resp.Result = s.blockchain.GetBlocks()
	default:
		resp.Error = "Unknown method"
		s.metrics.ErrorCount.WithLabelValues(req.Method).Inc()
	}

	return json.Marshal(resp)
}
