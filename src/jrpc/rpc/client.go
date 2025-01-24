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
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,q
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package rpc

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/rpc"
	"sync"
	"time"
)

// clientCodec implements the rpc.ClientCodec interface for JSON-RPC over HTTP.
type clientCodec struct {
	dec *json.Decoder // Decoder for reading JSON values
	enc *json.Encoder // Encoder for writing JSON values
	c   io.Closer     // Closer for the connection

	req  clientRequest  // Workspace for requests
	resp clientResponse // Workspace for responses

	mutex   sync.Mutex        // Protects access to pending requests
	pending map[uint64]string // Tracks request IDs to methods

	// Hooks for logging and debugging
	logRequest  func(request clientRequest)
	logResponse func(response clientResponse)
}

// CircuitBreaker structure to track failure count and timeout
type CircuitBreaker struct {
	failureCount int
	open         bool
	lastFailedAt time.Time
	timeout      time.Duration
	mu           sync.Mutex
}

// clientRequest represents a JSON-RPC request.
type clientRequest struct {
	Method string `json:"method"` // Method name
	Params [1]any `json:"params"` // Parameters
	Id     uint64 `json:"id"`     // Request ID
}

// clientResponse represents a JSON-RPC response.
type clientResponse struct {
	Id     uint64           `json:"id"`     // Response ID
	Result *json.RawMessage `json:"result"` // Result
	Error  any              `json:"error"`  // Error
}

// reset prepares a response for reuse.
func (r *clientResponse) reset() {
	r.Id = 0
	r.Result = nil
	r.Error = nil
}

// NewClientCodec initializes a new clientCodec.
func NewClientCodec(conn io.ReadWriteCloser, logRequest func(clientRequest), logResponse func(clientResponse)) rpc.ClientCodec {
	return &clientCodec{
		dec:         json.NewDecoder(conn),
		enc:         json.NewEncoder(conn),
		c:           conn,
		pending:     make(map[uint64]string),
		logRequest:  logRequest,
		logResponse: logResponse,
	}
}

// WriteRequest sends a JSON-RPC request, with retries for transient errors.
// WriteRequest sends a JSON-RPC request, with retries for transient errors.
func (c *clientCodec) WriteRequest(r *rpc.Request, param any) error {
	c.mutex.Lock()
	c.pending[r.Seq] = r.ServiceMethod
	c.mutex.Unlock()

	c.req.Method = r.ServiceMethod
	c.req.Params[0] = param
	c.req.Id = r.Seq

	// Track the start time for latency measurement
	startTime := time.Now()

	// Log the outgoing request if logging is enabled
	if c.logRequest != nil {
		c.logRequest(c.req)
	}

	// Retry logic for transient errors
	const maxRetries = 3
	for attempt := 1; attempt <= maxRetries; attempt++ {
		if err := c.enc.Encode(&c.req); err != nil {
			// On failure, increment error count and return
			IncrementErrorCount()
			if attempt == maxRetries {
				return fmt.Errorf("failed after %d attempts: %w", maxRetries, err)
			}
			time.Sleep(100 * time.Millisecond) // Backoff before retrying
			continue
		}
		break
	}

	// Calculate latency and add to metrics
	latency := time.Since(startTime)
	AddLatency(latency)

	// Increment the request count
	IncrementRequestCount()

	return nil
}

// ReadResponseHeader reads the JSON-RPC response header.
func (c *clientCodec) ReadResponseHeader(r *rpc.Response) error {
	c.resp.reset()
	startTime := time.Now()

	if err := c.dec.Decode(&c.resp); err != nil {
		// Increment error count on failure
		IncrementErrorCount()
		return err
	}

	c.mutex.Lock()
	r.ServiceMethod = c.pending[c.resp.Id]
	delete(c.pending, c.resp.Id)
	c.mutex.Unlock()

	r.Seq = c.resp.Id
	if c.resp.Error != nil {
		errMsg, ok := c.resp.Error.(string)
		if !ok {
			return fmt.Errorf("invalid error format: %v", c.resp.Error)
		}
		r.Error = errMsg
		// Increment error count for failed responses
		IncrementErrorCount()
	}

	// Calculate response time (latency) and add to metrics
	latency := time.Since(startTime)
	AddLatency(latency)

	// Log the incoming response if logging is enabled
	if c.logResponse != nil {
		c.logResponse(c.resp)
	}

	return nil
}

// ReadResponseBody unmarshals the response body into the provided object.
func (c *clientCodec) ReadResponseBody(x any) error {
	if x == nil {
		return nil
	}
	return json.Unmarshal(*c.resp.Result, x)
}

// Close closes the connection.
func (c *clientCodec) Close() error {
	return c.c.Close()
}

// NewClient creates a new rpc.Client with the specified codec.
func NewClient(conn io.ReadWriteCloser, logRequest func(clientRequest), logResponse func(clientResponse)) *rpc.Client {
	return rpc.NewClientWithCodec(NewClientCodec(conn, logRequest, logResponse))
}

// Dial establishes a connection to the server.
func Dial(network, address string) (*rpc.Client, error) {
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	return NewClient(conn, nil, nil), nil
}

// DialWithTimeout establishes a connection with a timeout.
func DialWithTimeout(network, address string, timeout time.Duration) (*rpc.Client, error) {
	conn, err := net.DialTimeout(network, address, timeout)
	if err != nil {
		return nil, err
	}
	return NewClient(conn, nil, nil), nil
}

// Call is a helper for synchronous JSON-RPC method calls.
func Call(client *rpc.Client, method string, args any, result any) error {
	return client.Call(method, args, result)
}

// BatchRequest sends multiple requests as a single batch for efficiency.
func BatchRequest(client *rpc.Client, requests []rpc.Request, results []any, args []any) error {
	if len(requests) != len(results) || len(requests) != len(args) {
		return errors.New("requests, results, and args length mismatch")
	}
	for i, req := range requests {
		// Call the service method with arguments from the args slice
		if err := client.Call(req.ServiceMethod, args[i], &results[i]); err != nil {
			return err
		}
	}
	return nil
}

// CircuitBreakerHandler is a wrapper around the CircuitBreaker to manage requests.
func (cb *CircuitBreaker) HandleRequest() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.open && time.Since(cb.lastFailedAt) < cb.timeout {
		return fmt.Errorf("circuit breaker is open, request not allowed")
	}

	if cb.open && time.Since(cb.lastFailedAt) > cb.timeout {
		// Reset the breaker after timeout
		cb.open = false
	}

	return nil
}

// ReportFailure increments the failure count and opens the circuit if needed.
func (cb *CircuitBreaker) ReportFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failureCount++
	if cb.failureCount >= 3 {
		cb.open = true
		cb.lastFailedAt = time.Now()
	}
}

// Reset resets the failure count and closes the circuit.
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failureCount = 0
	cb.open = false
}

// ConnectionPool manages a pool of connections.
type ConnectionPool struct {
	conns    []*rpc.Client
	mu       sync.Mutex
	maxConns int
}

// NewConnectionPool creates a new connection pool with a maximum number of connections.
func NewConnectionPool(maxConns int) *ConnectionPool {
	return &ConnectionPool{
		conns:    make([]*rpc.Client, 0, maxConns),
		maxConns: maxConns,
	}
}

// GetConnection retrieves a connection from the pool, or creates one if needed.
func (p *ConnectionPool) GetConnection(network, address string) (*rpc.Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.conns) > 0 {
		conn := p.conns[len(p.conns)-1]
		p.conns = p.conns[:len(p.conns)-1]
		return conn, nil
	}

	// Create a new connection if the pool is empty
	return Dial(network, address)
}

// ReturnConnection returns a connection to the pool.
func (p *ConnectionPool) ReturnConnection(client *rpc.Client) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.conns) < p.maxConns {
		p.conns = append(p.conns, client)
	}
}
