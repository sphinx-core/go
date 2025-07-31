// MIT License
//
// Copyright (c) 2024 sphinx-core
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

// go/src/rpc/types.go
package rpc

import (
	"hash"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sphinx-core/go/src/core"
	security "github.com/sphinx-core/go/src/handshake"
)

// NodeID represents a unique 256-bit node identifier.
type NodeID [32]byte

// Key represents a 256-bit key for the key-value store.
type Key [32]byte

// Codec provides binary encoding/decoding utilities.
type Codec struct{}

// RPCID represents a unique RPC request identifier.
type RPCID uint64

// GetRPCID generates a random non-zero RPCID.
func GetRPCID() RPCID {
	for {
		if v := rand.Uint64(); v != 0 {
			return RPCID(v)
		}
	}
}

// RPCType defines the type of RPC message.
type RPCType int8

// RPC message types.
const (
	RPCGetBlockCount RPCType = iota
	RPCGetBestBlockHash
	RPCGetBlock
	RPCGetBlocks
	RPCSendRawTransaction
	RPCGetTransaction
	RPCPing
	RPCJoin
	RPCFindNode
	RPCGet
	RPCStore
)

// Remote represents a remote node's address and ID.
type Remote struct {
	NodeID  NodeID
	Address net.UDPAddr
}

// Message represents an RPC message for P2P communication.
type Message struct {
	RPCType   RPCType
	Query     bool
	TTL       uint16 // TTL in seconds
	Target    NodeID
	RPCID     RPCID
	From      Remote
	Nodes     []Remote
	Values    [][]byte
	Iteration uint8
	Secret    uint16
}

// Metrics holds RPC-related Prometheus metrics.
type Metrics struct {
	RequestCount   *prometheus.CounterVec
	RequestLatency *prometheus.HistogramVec
	ErrorCount     *prometheus.CounterVec
}

// Server processes RPC requests.
type Server struct {
	messageCh    chan *security.Message
	metrics      *Metrics
	blockchain   *core.Blockchain
	handler      *JSONRPCHandler
	queryManager *QueryManager
	store        *KVStore
}

// JSONRPCRequest represents a JSON-RPC 2.0 request.
type JSONRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
	ID      interface{} `json:"id"`
}

// JSONRPCResponse represents a JSON-RPC 2.0 response.
type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
	ID      interface{} `json:"id"`
}

// RPCError represents a JSON-RPC error object.
type RPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// RPCHandler defines a function type for handling RPC methods.
type RPCHandler func(params interface{}) (interface{}, error)

// JSONRPCHandler manages JSON-RPC request processing.
type JSONRPCHandler struct {
	server  *Server
	methods map[string]RPCHandler
}

// requestStatus tracks the status of a request to a node.
type requestStatus struct {
	Timeout   bool
	Responded bool
}

// Query represents an ongoing query session.
type Query struct {
	onCompletion func()
	pending      int
	start        time.Time
	RPCID        RPCID
	Target       NodeID
	Requested    map[NodeID]*requestStatus
}

// join tracks join requests.
type join struct {
	start time.Time
}

// ping tracks ping requests.
type ping struct {
	start     time.Time
	requested map[NodeID]struct{}
}

// get tracks get requests.
type get struct {
	start time.Time
}

// QueryManager manages ongoing queries.
type QueryManager struct {
	findNode map[RPCID]*Query
	join     map[RPCID]*join
	ping     map[RPCID]*ping
	get      map[RPCID]*get
}

const (
	// expiredInterval defines the expiration time for queries.
	expiredInterval = 10 * time.Second
)

// checksum represents a hash checksum for deduplication.
type checksum struct {
	v1 uint64
	v2 uint64
	v3 uint64
	v4 uint64
}

// stored represents a stored key-value entry with TTL.
type stored struct {
	ttl      time.Time
	values   [][]byte
	included map[checksum]struct{}
}

// KVStore is an in-memory key-value store.
type KVStore struct {
	mu   sync.Mutex
	hash hash.Hash
	data map[Key]*stored
}
