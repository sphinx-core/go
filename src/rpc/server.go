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

// go/src/rpc/server.go
package rpc

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sphinx-core/go/src/core"
	types "github.com/sphinx-core/go/src/core/transaction"
	"github.com/sphinx-core/go/src/security"
)

// NewServer creates a new RPC server.
func NewServer(messageCh chan *security.Message, blockchain *core.Blockchain) *Server {
	metrics := NewMetrics()
	prometheus.MustRegister(metrics.RequestCount, metrics.RequestLatency, metrics.ErrorCount)
	return &Server{
		messageCh:  messageCh,
		metrics:    metrics,
		blockchain: blockchain,
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
	defer func() {
		s.metrics.RequestLatency.WithLabelValues(req.Method).Observe(time.Since(start).Seconds())
	}()

	resp := JSONRPCResponse{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "add_transaction":
		var tx types.Transaction
		if err := json.Unmarshal([]byte(req.Params.(string)), &tx); err != nil {
			s.metrics.ErrorCount.WithLabelValues(req.Method).Inc()
			return nil, err
		}
		if err := s.blockchain.AddTransaction(&tx); err != nil {
			s.metrics.ErrorCount.WithLabelValues(req.Method).Inc()
			return nil, err
		}
		s.messageCh <- &security.Message{Type: "transaction", Data: &tx}
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
