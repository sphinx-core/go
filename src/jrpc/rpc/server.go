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
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/rpc"
	"sync"
	"time"
)

// Error variables for handling missing parameters and invalid sequence numbers
var (
	errMissingParams = errors.New("jsonrpc: request body missing params") // Error for missing parameters in the request
	errInvalidSeq    = errors.New("invalid sequence number in response")  // Error for invalid sequence numbers in responses
	null             = json.RawMessage([]byte("null"))                    // Null value is used for invalid or empty requests
)

// ServerCodec interface defines methods to read, write, and close an RPC connection
type ServerCodec interface {
	ReadRequestHeader(*rpc.Request) error           // Reads and decodes the header of an RPC request, extracting method info
	ReadRequestBody(interface{}) error              // Reads and decodes the body of an RPC request, extracting the parameters
	WriteResponse(*rpc.Response, interface{}) error // Serializes and sends back the response for an RPC call
	Close() error
}

// serverCodec implements the rpc.ServerCodec interface for handling requests and responses.
type serverCodec struct {
	dec      *json.Decoder               // JSON decoder for reading incoming requests
	enc      *json.Encoder               // JSON encoder for sending responses
	c        io.Closer                   // The connection object
	req      serverRequest               // Temporary object to store the current request data
	mutex    sync.RWMutex                // Mutex to protect concurrent access to shared resources
	seq      uint64                      // Sequence number for each request
	pending  map[uint64]*json.RawMessage // Map to store pending requests by sequence number
	PeerInfo PeerInfo                    // Peer connection details
}

// CircuitBreaker tracks failure count and handles connection timeouts.
type CircuitBreaker struct {
	failureCount int           // Tracks the number of failures
	open         bool          // Indicates if the circuit is open or closed
	lastFailedAt time.Time     // Time of the last failure
	timeout      time.Duration // Time to wait before resetting the circuit
	mu           sync.Mutex    // Mutex to protect concurrent access to the CircuitBreaker
}

// ConnectionPool manages a pool of reusable connections.
type ConnectionPool struct {
	conns    []*rpc.Client // List of active connections in the pool
	mu       sync.Mutex    // Mutex to protect access to the connection pool
	maxConns int           // Maximum number of connections allowed in the pool
}

// serverRequest represents the structure of a JSON-RPC request.
type serverRequest struct {
	Method string           `json:"method"` // The name of the RPC method being called
	Params *json.RawMessage `json:"params"` // The parameters for the method (encoded as JSON)
	Id     *json.RawMessage `json:"id"`     // The unique ID for the request
}

// Reset resets the fields of the serverRequest to prepare for a new request.
func (r *serverRequest) reset() {
	// Clear all fields of the request
	r.Method = ""
	r.Params = nil
	r.Id = nil
}

// serverResponse represents the structure of a JSON-RPC response.
type serverResponse struct {
	Id     *json.RawMessage `json:"id"`     // The request ID for matching response
	Result any              `json:"result"` // The result of the RPC method execution
	Error  any              `json:"error"`  // Any error message if the RPC call fails
}

// PeerInfo struct for storing information about client connections based on RFC 2-like protocols
type PeerInfo struct {
	// Transport indicates the protocol used for communication (e.g., HTTP, WebSocket, or IPC).
	// This could be extended to include "ws" for WebSocket or "ipc" for Inter-process communication.
	Transport string

	// RemoteAddr holds the address of the client, typically containing the client's IP address and port.
	// This is key for identifying the client during interactions.
	RemoteAddr string

	// HTTP-specific information that is relevant for connections using the HTTP protocol.
	// This helps provide context about the client's HTTP request headers.
	HTTP struct {
		// Version specifies the HTTP version used by the client (e.g., "HTTP/1.1" or "HTTP/2").
		// Not applicable for WebSocket, but can be extended for HTTP-based protocols.
		Version string

		// UserAgent holds the value of the 'User-Agent' header, which can be used to identify the client's software.
		UserAgent string

		// Origin represents the 'Origin' header, often used in CORS scenarios to track the source of the request.
		// Could also be used for WebSocket handshakes.
		Origin string

		// Host indicates the 'Host' header which specifies the domain and port number for HTTP requests.
		Host string
	}

	// Timestamp represents the time the connection was established. Useful for monitoring and auditing.
	Timestamp time.Time

	// ProtocolVersion indicates the version of the peer protocol in use, potentially for negotiation.
	// Example: "2.0" for JSON-RPC 2.0 compliance.
	ProtocolVersion string

	// ConnectionID is a unique identifier for the client connection. This helps track and identify sessions.
	ConnectionID string

	HeaderInfo string // Stores the decoded header information
}

// NewConnectionPool creates a new connection pool with the specified maximum connections.
func NewConnectionPool(maxConns int) *ConnectionPool {
	return &ConnectionPool{
		conns:    make([]*rpc.Client, 0, maxConns), // Initializes the connection pool
		maxConns: maxConns,                         // Sets the maximum number of connections
	}
}

// isBatch returns true when the first non-whitespace characters is '['
func isBatch(raw json.RawMessage) bool {
	for _, c := range raw {
		// skip insignificant whitespace (http://www.ietf.org/rfc/rfc4627.txt)
		if c == 0x20 || c == 0x09 || c == 0x0a || c == 0x0d {
			continue
		}
		return c == '['
	}
	return false
}

// ProcessBatch handles a batch of JSON-RPC requests.
// It validates whether the input is a batch request, unmarshals the requests,
// executes them via the BatchRequest function, and processes the results.
func ProcessBatch(client *rpc.Client, raw json.RawMessage) error {
	// Check if the input JSON is a batch request
	if !isBatch(raw) {
		return errors.New("input JSON is not a batch request")
	}

	// Parse the batch requests from the raw JSON
	var requests []rpc.Request
	if err := json.Unmarshal(raw, &requests); err != nil {
		return errors.New("failed to parse batch requests: " + err.Error())
	}

	// Initialize slices for storing results and arguments for each request
	results := make([]any, len(requests))
	args := make([]any, len(requests))

	// Populate arguments for each request
	// In a real-world use case, this should be customized to initialize arguments correctly
	for i := range args {
		args[i] = map[string]any{} // Placeholder for argument initialization
	}

	// Execute the batch requests using the BatchRequest function
	if err := BatchRequest(client, requests, results, args); err != nil {
		return err // Return an error if any request fails
	}

	// Process the results of each request
	for _, result := range results {
		// Serialize the result to JSON and print it (example behavior)
		if resJSON, err := json.Marshal(result); err == nil {
			println(string(resJSON)) // Output the result as a JSON string
		} else {
			return errors.New("failed to process result: " + err.Error()) // Handle serialization error
		}
	}

	return nil // Return nil if all requests and results were successfully processed
}

// CreateHTTPClient configures and returns a custom HTTP client
func CreateHTTPClient() *http.Client {
	// Create and configure the HTTP transport layer with connection pooling and timeouts
	transport := &http.Transport{
		MaxIdleConns:        100,              // Set the maximum number of idle connections to keep open
		MaxIdleConnsPerHost: 50,               // Set the maximum number of idle connections per host
		IdleConnTimeout:     90 * time.Second, // Set the timeout duration for idle connections
		// Configure the dial context for establishing new TCP connections
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second, // Set the timeout for establishing a new connection
			KeepAlive: 30 * time.Second, // Set the keep-alive period for idle connections
		}).DialContext,
	}
	// Return the HTTP client configured with the custom transport
	return &http.Client{Transport: transport}
}

// AsyncCall executes an RPC call asynchronously and returns a channel to handle the response.
func AsyncCall(client *rpc.Client, serviceMethod string, args any) <-chan *rpc.Call {
	// Create a channel to receive the result of the asynchronous call
	done := make(chan *rpc.Call, 1)
	// Launch a goroutine to perform the RPC call asynchronously
	go func() {
		// Use the client to make a Go RPC call (asynchronous)
		client.Go(serviceMethod, args, nil, done)
	}()
	// Return the channel to monitor the call result
	return done
}

// NewServerCodec creates a new instance of serverCodec to handle the RPC communication.
func NewServerCodec(conn io.ReadWriteCloser, peer PeerInfo) rpc.ServerCodec {
	// Cast the connection to WebSocketConnWrapper
	wsConn, ok := conn.(*WebSocketConnWrapper)
	if !ok {
		// Handle the case where the connection is not a WebSocketConnWrapper
		log.Fatal("Connection is not a WebSocketConnWrapper")
	}
	// Return a new serverCodec instance with the wrapped connection
	return &serverCodec{
		dec:      json.NewDecoder(wsConn),
		enc:      json.NewEncoder(wsConn),
		c:        wsConn,
		pending:  make(map[uint64]*json.RawMessage),
		PeerInfo: peer, // Add peer information
	}
}

// ReadRequestHeader reads and decodes the header of the incoming request, then unmarshals it into the serverRequest structure.
func (c *serverCodec) ReadRequestHeader(r *rpc.Request) error {
	// Reset the current request object to prepare for reading new data.
	c.req.reset()

	// Initialize a slice to hold the raw message that will be received.
	rawMessage := []byte{}

	// Decode the incoming message into the rawMessage slice.
	// This reads the raw byte data from the WebSocket connection.
	if err := c.dec.Decode(&rawMessage); err != nil {
		// Log an error message if decoding the raw message fails.
		log.Printf("Error decoding raw message: %v", err)
		return err // Return the error to the caller.
	}

	// Log the raw message received to help with debugging or logging.
	// This shows the exact raw data as it was received before any processing.
	log.Printf("Raw message received: %s", string(rawMessage))

	// Unmarshal the raw message (which is in JSON format) into the serverRequest struct.
	// This deserializes the incoming JSON payload into the fields of serverRequest.
	if err := json.Unmarshal(rawMessage, &c.req); err != nil {
		// Log an error message if unmarshalling the raw message into serverRequest fails.
		log.Printf("Error unmarshalling message into serverRequest: %v", err)
		return err // Return the error to the caller.
	}

	// Check if this is a batch request
	if isBatch(*c.req.Params) {
		var batchRequests []serverRequest
		if err := json.Unmarshal(*c.req.Params, &batchRequests); err != nil {
			return err
		}
		log.Printf("Batch request detected")
	}

	// Once unmarshalled, set the service method in the rpc.Request object.
	// This helps the RPC server understand which method to call for this request.
	r.ServiceMethod = c.req.Method

	// Lock the mutex to ensure that the sequence number and pending requests are modified safely.
	c.mutex.Lock()

	// Increment the sequence number for the current request.
	// This helps to uniquely identify and track requests and responses.
	c.seq++

	// Store the request ID in the pending map using the sequence number as the key.
	// This allows us to associate a response with its corresponding request.
	c.pending[c.seq] = c.req.Id

	// Set the sequence number in the rpc.Request object.
	// This helps the RPC server track the response's sequence number.
	r.Seq = c.seq

	// Unlock the mutex after the sequence number and pending map are modified.
	c.mutex.Unlock()

	// Return nil to indicate that the header has been successfully read and processed.
	return nil
}

// ReadRequestBody unmarshals the body of the request (parameters) into the provided value.
func (c *serverCodec) ReadRequestBody(x any) error {
	// Lock the mutex to ensure thread-safe access to the shared state (c.req and c.req.Params).
	c.mutex.Lock()
	// Ensure the mutex is unlocked once the function exits, even if an error occurs.
	defer c.mutex.Unlock()

	// If the provided value (x) is nil, there is no need to proceed, so return nil.
	if x == nil {
		return nil
	}

	// If the request parameters (c.req.Params) are nil, return an error indicating missing parameters.
	if c.req.Params == nil {
		return errMissingParams
	}

	// Create a temporary array to hold the unmarshalled parameters.
	var params [1]any
	// Assign the provided value (x) to the first element of the params array.
	params[0] = x

	// Unmarshal the JSON-encoded request parameters into the params array.
	// The "Params" field in the request is expected to be a raw JSON message, so it's unmarshalled into the params.
	return json.Unmarshal(*c.req.Params, &params)
}

// WriteResponse encodes and writes the response back to the connection.
func (c *serverCodec) WriteResponse(r *rpc.Response, x any) error {
	// Lock the mutex to ensure thread-safe access to shared resources
	c.mutex.Lock()
	// Retrieve the request ID corresponding to the sequence number in the response
	id, ok := c.pending[r.Seq]
	// Remove the entry for the sequence number from the pending map
	delete(c.pending, r.Seq)
	// Unlock the mutex after modifying shared resources
	c.mutex.Unlock()

	// If no corresponding request ID was found, return an error
	if !ok {
		log.Printf("Invalid sequence number: %v", r.Seq)
		return errInvalidSeq
	}

	// If the request ID is nil, use the predefined null value for the response
	if id == nil {
		id = &null
	}

	// Create the serverResponse object to hold the response data
	resp := serverResponse{Id: id}
	// If there's no error in the response, set the result; otherwise, set the error
	if r.Error == "" {
		resp.Result = x
	} else {
		resp.Error = r.Error
	}

	// Log the response data before sending
	log.Printf("Sending response: %+v", resp)
	// Encode the response as JSON and send it to the connection
	return c.enc.Encode(resp)
}

// Close closes the underlying connection after the RPC communication is complete.
func (c *serverCodec) Close() error {
	// Close the connection and return any error encountered
	return c.c.Close()
}

// ServeConn processes a single RPC connection and starts serving the RPC codec.
func ServeConn(conn io.ReadWriteCloser, peer PeerInfo) {
	// Pass PeerInfo to NewServerCodec
	rpc.ServeCodec(NewServerCodec(conn, peer))
}

// HandleRPC processes incoming HTTP requests and serves RPC over HTTP.
// It performs several critical tasks, such as ensuring the HTTP method is POST,
// extracting client connection details, and serving the connection as an RPC server.
func HandleRPC(w http.ResponseWriter, r *http.Request) {
	// Ensure that the incoming HTTP request uses the POST method.
	// JSON-RPC over HTTP strictly requires POST for sending requests.
	if r.Method != http.MethodPost {
		http.Error(w, "JSON-RPC server only accepts POST requests", http.StatusMethodNotAllowed)
		return
	}

	// Check if the ResponseWriter supports connection hijacking.
	// Hijacking is required to take control of the connection for raw socket communication.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		// If the server does not support hijacking, respond with an internal server error.
		http.Error(w, "Server does not support connection hijacking", http.StatusInternalServerError)
		return
	}

	// Hijack the HTTP connection to take control of the underlying TCP connection.
	// This is necessary for bypassing the standard HTTP handling to process JSON-RPC requests.
	conn, _, err := hijacker.Hijack()
	if err != nil {
		// If hijacking the connection fails, respond with an error.
		http.Error(w, "Failed to hijack connection: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Populate the PeerInfo struct with details about the client connection.
	// This information is useful for logging, debugging, and tracking connections.
	peer := PeerInfo{
		Transport:  "http",                     // Specify the transport protocol used (HTTP in this case).
		RemoteAddr: conn.RemoteAddr().String(), // Get the client's remote address (IP and port).
	}
	peer.HTTP.Version = r.Proto               // Extract the HTTP protocol version (e.g., "HTTP/1.1").
	peer.HTTP.UserAgent = r.UserAgent()       // Extract the User-Agent header sent by the client.
	peer.HTTP.Origin = r.Header.Get("Origin") // Extract the Origin header, if present (useful for CORS).
	peer.HTTP.Host = r.Host                   // Get the host value from the HTTP request.

	// Log the client connection details for monitoring and debugging purposes.
	// This provides visibility into who is connecting to the server.
	log.Printf("New RPC connection from: %+v", peer)

	// Process the hijacked connection as an RPC connection in a separate goroutine.
	// The ServeConn function handles incoming RPC requests over the connection.
	go ServeConn(conn, peer)
}

// Graceful shutdown function to handle server shutdown with a timeout.
func ShutdownServer(srv *http.Server, timeout time.Duration) error {
	// Log the server shutdown initiation
	log.Println("Initiating server shutdown...")
	// Create a context with a timeout to allow existing connections to close gracefully
	shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel() // Ensure the cancel function is called after shutdown completes

	// Initiate the server shutdown and return any error that occurs during shutdown
	return srv.Shutdown(shutdownCtx)
}
