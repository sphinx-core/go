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
	dec *json.Decoder // Decoder for reading JSON values from the network connection
	enc *json.Encoder // Encoder for writing JSON values to the network connection
	c   io.Closer     // Closer for the connection, implements io.Closer interface

	req  clientRequest  // Workspace to hold the current request
	resp clientResponse // Workspace to hold the current response

	mutex   sync.Mutex        // Mutex to protect access to pending requests
	pending map[uint64]string // Tracks pending requests by their unique IDs

	// Hooks for logging and debugging purposes
	logRequest  func(request clientRequest)
	logResponse func(response clientResponse)
}

// clientRequest represents a JSON-RPC request structure.
// This structure is used to send method calls from the client to the server.
// - Method: Specifies the name of the method to be invoked on the server.
// - Params: Contains the parameters required by the method. This is currently an array with one parameter.
// - Id: A unique identifier for the request, allowing responses to be matched with their corresponding requests.
type clientRequest struct {
	Method string `json:"method"` // The method to be called on the server.
	Params [1]any `json:"params"` // An array containing the parameters for the method (currently supports one parameter).
	Id     uint64 `json:"id"`     // Unique identifier for the request, enabling tracking and matching with the response.
}

// clientResponse represents a JSON-RPC response structure.
// This structure is used to receive responses from the server after a method call.
// - Id: The unique identifier of the request, used to match the response to its corresponding request.
// - Result: Holds the result of the method call if it was successful. It is a pointer to allow optional absence of a value.
// - Error: Contains error information if the method call fails.
type clientResponse struct {
	Id     uint64           `json:"id"`     // Response ID, matching the request's ID.
	Result *json.RawMessage `json:"result"` // Pointer to the result of the method call (nil if an error occurred).
	Error  any              `json:"error"`  // Error information returned by the server (nil if the call was successful).
}

// Codec defines an interface for implementing various JSON-RPC codecs.
// A codec is responsible for encoding requests, decoding responses, and managing the connection lifecycle.
// - WriteRequest: Encodes and sends a JSON-RPC request.
// - ReadResponseHeader: Reads and decodes the response header, identifying the associated method and handling errors.
// - ReadResponseBody: Reads and decodes the response body, extracting the method's result.
// - Close: Closes the underlying connection or resources used by the codec.
type Codec interface {
	WriteRequest(r *Request, param any) error // Encodes and sends a request to the server.
	ReadResponseHeader(r *Response) error     // Decodes the response header from the server.
	ReadResponseBody(x any) error             // Decodes the response body into the provided object.
	Close() error                             // Closes the codec and its resources.
}

// reset prepares the response structure for reuse by clearing its fields.
// This is useful for scenarios where the response object is reused multiple times
// to avoid residual data from previous calls.
// - Id: Reset to 0 to indicate a fresh state.
// - Result: Reset to nil, clearing any previous method results.
// - Error: Reset to nil, clearing any previous error information.
func (r *clientResponse) reset() {
	r.Id = 0       // Reset the response ID to its initial state.
	r.Result = nil // Clear any existing result from previous calls.
	r.Error = nil  // Clear any error details from previous calls.
}

// NewClientCodec initializes a new clientCodec, sets up the decoder, encoder, and connection.
func NewClientCodec(conn io.ReadWriteCloser, logRequest func(clientRequest), logResponse func(clientResponse)) rpc.ClientCodec {
	return &clientCodec{
		dec:         json.NewDecoder(conn),   // Initializes a new JSON decoder with the connection
		enc:         json.NewEncoder(conn),   // Initializes a new JSON encoder with the connection
		c:           conn,                    // Assigns the connection
		pending:     make(map[uint64]string), // Creates an empty map for pending requests
		logRequest:  logRequest,              // Assigns the logRequest function
		logResponse: logResponse,             // Assigns the logResponse function
	}
}

// WriteRequest sends a JSON-RPC request, with retry logic for transient errors.
func (c *clientCodec) WriteRequest(r *rpc.Request, param any) error {
	c.mutex.Lock()                     // Locks the mutex to prevent race conditions
	c.pending[r.Seq] = r.ServiceMethod // Maps the request sequence number to the service method
	c.mutex.Unlock()                   // Unlocks the mutex after updating the pending map

	c.req.Method = r.ServiceMethod // Sets the method name from the request
	c.req.Params[0] = param        // Sets the parameters for the method
	c.req.Id = r.Seq               // Sets the request ID

	// Track the start time to measure request latency
	startTime := time.Now()

	// Log the outgoing request if a logging function is provided
	if c.logRequest != nil {
		c.logRequest(c.req)
	}

	// Retry logic for transient errors, tries up to 3 times
	const maxRetries = 3
	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Tries to encode the request into JSON format and send it over the network
		if err := c.enc.Encode(&c.req); err != nil {
			IncrementErrorCount() // Increments the error count if the encoding fails
			if attempt == maxRetries {
				return fmt.Errorf("failed after %d attempts: %w", maxRetries, err)
			}
			time.Sleep(100 * time.Millisecond) // Waits before retrying
			continue
		}
		break // Exit the loop if encoding is successful
	}

	// Calculate the latency of the request and add it to the metrics
	latency := time.Since(startTime)
	AddLatency(latency)

	// Increment the request count for monitoring purposes
	IncrementRequestCount()

	return nil
}

// ReadResponseHeader reads the header of the JSON-RPC response.
func (c *clientCodec) ReadResponseHeader(r *rpc.Response) error {
	c.resp.reset() // Resets the response object to prepare for reuse
	startTime := time.Now()

	// Decodes the response header from the network into the resp object
	if err := c.dec.Decode(&c.resp); err != nil {
		IncrementErrorCount() // Increments error count if decoding fails
		return err
	}

	c.mutex.Lock()                         // Locks the mutex for safe concurrent access
	r.ServiceMethod = c.pending[c.resp.Id] // Retrieves the service method for the response ID
	delete(c.pending, c.resp.Id)           // Removes the pending request after processing
	c.mutex.Unlock()                       // Unlocks the mutex

	r.Seq = c.resp.Id        // Sets the response sequence ID
	if c.resp.Error != nil { // If there is an error in the response
		errMsg, ok := c.resp.Error.(string) // Type assertion to string
		if !ok {
			return fmt.Errorf("invalid error format: %v", c.resp.Error)
		}
		r.Error = errMsg      // Sets the error message for the response
		IncrementErrorCount() // Increments the error count for failed responses
	}

	// Calculate the latency of the response and add it to the metrics
	latency := time.Since(startTime)
	AddLatency(latency)

	// Log the incoming response if a logging function is provided
	if c.logResponse != nil {
		c.logResponse(c.resp)
	}

	return nil
}

// ReadResponseBody unmarshals the response body into the provided object.
func (c *clientCodec) ReadResponseBody(x any) error {
	if x == nil {
		return nil // If the response body is nil, nothing to unmarshal
	}
	// Unmarshals the response body into the provided object
	return json.Unmarshal(*c.resp.Result, x)
}

// Close closes the network connection.
func (c *clientCodec) Close() error {
	return c.c.Close() // Closes the connection by calling the Close method of the connection
}

// NewClient creates and returns a new rpc.Client instance with the specified codec.
func NewClient(conn io.ReadWriteCloser, logRequest func(clientRequest), logResponse func(clientResponse)) *rpc.Client {
	return rpc.NewClientWithCodec(NewClientCodec(conn, logRequest, logResponse)) // Creates and returns a new RPC client
}

// Dial establishes a connection to the server using the specified network and address.
func Dial(network, address string) (*rpc.Client, error) {
	conn, err := net.Dial(network, address) // Establishes a network connection
	if err != nil {
		return nil, err // Returns an error if the connection fails
	}
	return NewClient(conn, nil, nil), nil // Returns a new RPC client with the connection
}

// DialWithTimeout establishes a connection with a specified timeout duration.
func DialWithTimeout(network, address string, timeout time.Duration) (*rpc.Client, error) {
	conn, err := net.DialTimeout(network, address, timeout) // Establishes a connection with a timeout
	if err != nil {
		return nil, err // Returns an error if the connection fails
	}
	return NewClient(conn, nil, nil), nil // Returns a new RPC client with the connection
}

// BatchRequest sends multiple requests in a single batch for efficiency.
func BatchRequest(client *rpc.Client, requests []rpc.Request, results []any, args []any) error {
	if len(requests) != len(results) || len(requests) != len(args) {
		return errors.New("requests, results, and args length mismatch") // Returns an error if lengths do not match
	}
	// Iterates through the requests and calls the corresponding service method
	for i, req := range requests {
		if err := client.Call(req.ServiceMethod, args[i], &results[i]); err != nil {
			return err // Returns error if any request fails
		}
	}
	return nil // Returns nil if all requests were successful
}

// CircuitBreakerHandler manages the circuit breaker state and handles requests.
func (cb *CircuitBreaker) HandleRequest() error {
	cb.mu.Lock() // Locks the mutex to ensure safe concurrent access
	defer cb.mu.Unlock()

	// If the circuit is open and the timeout has not passed, reject the request
	if cb.open && time.Since(cb.lastFailedAt) < cb.timeout {
		return fmt.Errorf("circuit breaker is open, request not allowed")
	}

	// If the circuit is open and the timeout has passed, reset the circuit
	if cb.open && time.Since(cb.lastFailedAt) > cb.timeout {
		cb.open = false
	}

	return nil
}

// ReportFailure increments the failure count and opens the circuit if needed.
func (cb *CircuitBreaker) ReportFailure() {
	cb.mu.Lock() // Locks the mutex to ensure safe concurrent access
	defer cb.mu.Unlock()

	cb.failureCount++         // Increments the failure count
	if cb.failureCount >= 3 { // Opens the circuit if failure count exceeds threshold
		cb.open = true
		cb.lastFailedAt = time.Now() // Records the time of failure
	}
}

// Reset resets the failure count and closes the circuit breaker.
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock() // Locks the mutex to ensure safe concurrent access
	defer cb.mu.Unlock()

	cb.failureCount = 0 // Resets the failure count
	cb.open = false     // Closes the circuit
}

// GetConnection retrieves a connection from the pool or creates a new one if needed.
func (p *ConnectionPool) GetConnection(network, address string) (*rpc.Client, error) {
	p.mu.Lock() // Locks the mutex to ensure safe concurrent access
	defer p.mu.Unlock()

	// If there are connections available in the pool, return the last one
	if len(p.conns) > 0 {
		conn := p.conns[len(p.conns)-1]
		p.conns = p.conns[:len(p.conns)-1] // Removes the last connection from the pool
		return conn, nil
	}

	// If no connections are available, create a new one
	return Dial(network, address)
}

// ReturnConnection returns a connection to the pool for reuse.
func (p *ConnectionPool) ReturnConnection(client *rpc.Client) {
	p.mu.Lock() // Locks the mutex to ensure safe concurrent access
	defer p.mu.Unlock()

	// If the number of connections in the pool is below the maximum, add the connection to the pool
	if len(p.conns) < p.maxConns {
		p.conns = append(p.conns, client)
	}
}

// WriteRequest sends an RPC request over the WebSocket connection.
func (c *ClientCodecWebSocket) WriteRequest(req *Request, args interface{}) error {
	// Send the RPC request over WebSocket as a JSON message
	err := c.conn.WriteJSON(req)
	if err != nil {
		return err
	}

	// Send the arguments (args) for the RPC call as a JSON message
	return c.conn.WriteJSON(args)
}

// Close closes the WebSocket connection.
func (c *ClientCodecWebSocket) Close() error {
	return c.conn.Close()
}
