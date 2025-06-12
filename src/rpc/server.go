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

	"github.com/sphinx-core/go/src/core"
	types "github.com/sphinx-core/go/src/core/transaction"
	"github.com/sphinx-core/go/src/security"
)

// NewServer creates a new RPC server instance.
func NewServer(messageCh chan *security.Message, blockchain *core.Blockchain) *Server {
	metrics := NewMetrics() // Initialize Prometheus metrics singleton
	return &Server{
		messageCh:  messageCh,  // Channel to send security messages (e.g., transactions)
		metrics:    metrics,    // Metrics to track RPC performance/errors
		blockchain: blockchain, // Reference to the blockchain instance for handling requests
	}
}

// HandleRequest processes an incoming JSON-RPC request and returns a response.
func (s *Server) HandleRequest(data []byte) ([]byte, error) {
	var req JSONRPCRequest                             // Declare variable to hold decoded request
	if err := json.Unmarshal(data, &req); err != nil { // Decode JSON data into req struct
		s.metrics.ErrorCount.WithLabelValues("unknown").Inc() // Increment error count labeled "unknown"
		return nil, err                                       // Return error if JSON invalid
	}

	start := time.Now()                                      // Record start time for latency measurement
	s.metrics.RequestCount.WithLabelValues(req.Method).Inc() // Increment count of requests for this method
	defer func() {
		// After function ends, observe elapsed time and record latency for this method
		s.metrics.RequestLatency.WithLabelValues(req.Method).Observe(time.Since(start).Seconds())
	}()

	resp := JSONRPCResponse{JSONRPC: "2.0", ID: req.ID} // Prepare base response with JSON-RPC version and ID

	switch req.Method { // Switch based on the requested method name
	case "add_transaction": // Handle adding a transaction
		var tx types.Transaction                                                 // Declare transaction variable
		if err := json.Unmarshal([]byte(req.Params.(string)), &tx); err != nil { // Decode transaction from params string
			s.metrics.ErrorCount.WithLabelValues(req.Method).Inc() // Increment error count for this method
			return nil, err                                        // Return error if unmarshalling fails
		}
		if err := s.blockchain.AddTransaction(&tx); err != nil { // Add transaction to blockchain
			s.metrics.ErrorCount.WithLabelValues(req.Method).Inc() // Increment error count on failure
			return nil, err
		}
		s.messageCh <- &security.Message{Type: "transaction", Data: &tx}  // Send transaction message to message channel
		resp.Result = map[string]string{"status": "Transaction received"} // Set success result message

	case "getblockcount": // Return the current blockchain block count
		resp.Result = s.blockchain.GetBlockCount()

	case "getbestblockhash": // Return best (latest) block hash as a hex string
		resp.Result = fmt.Sprintf("%x", s.blockchain.GetBestBlockHash())

	case "getblock": // Return a specific block by hash
		var hash string                                                            // Variable to hold decoded hash string
		if err := json.Unmarshal([]byte(req.Params.(string)), &hash); err != nil { // Decode hash param string
			s.metrics.ErrorCount.WithLabelValues(req.Method).Inc() // Error count increment on failure
			return nil, err
		}
		hashBytes, err := hex.DecodeString(hash) // Decode hex string to byte slice
		if err != nil {
			s.metrics.ErrorCount.WithLabelValues(req.Method).Inc()
			return nil, err
		}
		block, err := s.blockchain.GetBlockByHash(hashBytes) // Retrieve block from blockchain by hash bytes
		if err != nil {
			s.metrics.ErrorCount.WithLabelValues(req.Method).Inc()
			return nil, err
		}
		resp.Result = block // Set the found block as the result

	case "getblocks": // Return all blocks in the blockchain
		resp.Result = s.blockchain.GetBlocks()

	default: // Unknown method case
		resp.Error = "Unknown method"                          // Set error message in response
		s.metrics.ErrorCount.WithLabelValues(req.Method).Inc() // Increment error count for unknown method
	}
	return json.Marshal(resp) // Marshal the response struct to JSON bytes and return
}
