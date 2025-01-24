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
)

// Null value is used for invalid or empty requests
var null = json.RawMessage([]byte("null"))

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

// serverCodec implements the rpc.ServerCodec interface for handling requests and responses.
type serverCodec struct {
	dec     *json.Decoder               // JSON decoder for reading incoming requests
	enc     *json.Encoder               // JSON encoder for sending responses
	c       io.Closer                   // The connection object
	req     serverRequest               // Temporary object to store the current request data
	mutex   sync.RWMutex                // Mutex to protect concurrent access to shared resources
	seq     uint64                      // Sequence number for each request
	pending map[uint64]*json.RawMessage // Map to store pending requests by sequence number
}

// NewServerCodec creates a new instance of serverCodec to handle the RPC communication
func NewServerCodec(conn io.ReadWriteCloser) rpc.ServerCodec {
	// Return a new serverCodec with initialized fields
	return &serverCodec{
		dec:     json.NewDecoder(conn),             // Initialize the JSON decoder for the connection
		enc:     json.NewEncoder(conn),             // Initialize the JSON encoder for the connection
		c:       conn,                              // Set the connection object
		pending: make(map[uint64]*json.RawMessage), // Initialize the map to track pending requests
	}
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

// ReadRequestHeader reads and decodes the header of the incoming request.
func (c *serverCodec) ReadRequestHeader(r *rpc.Request) error {
	// Reset the request object to prepare for reading a new request
	c.req.reset()
	// Decode the JSON request header into the serverRequest object
	if err := c.dec.Decode(&c.req); err != nil {
		// Log and return an error if decoding fails
		log.Printf("Error decoding request header: %v", err)
		return err
	}
	// Set the service method name in the rpc.Request object
	r.ServiceMethod = c.req.Method

	// Lock the mutex to ensure thread-safe access to shared resources
	c.mutex.Lock()
	// Increment the sequence number for the new request
	c.seq++
	// Map the sequence number to the request ID for tracking the request
	c.pending[c.seq] = c.req.Id
	// Set the sequence number in the rpc.Request object
	r.Seq = c.seq
	// Unlock the mutex after modifying shared resources
	c.mutex.Unlock()

	// Return nil indicating successful header read
	return nil
}

// ReadRequestBody unmarshals the body of the request (parameters) into the provided value.
func (c *serverCodec) ReadRequestBody(x any) error {
	// If the provided value is nil, return without doing anything
	if x == nil {
		return nil
	}
	// If no parameters are provided in the request, return an error
	if c.req.Params == nil {
		return errMissingParams
	}

	// Prepare a single-element array to hold the unmarshalled parameters
	var params [1]any
	// Assign the provided value to the first element of the array
	params[0] = x
	// Unmarshal the JSON parameters into the array
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
func ServeConn(conn io.ReadWriteCloser) {
	// Serve the connection using the NewServerCodec to handle RPC requests and responses
	rpc.ServeCodec(NewServerCodec(conn))
}

// HandleRPC processes incoming HTTP requests and serves RPC over HTTP.
func HandleRPC(w http.ResponseWriter, r *http.Request) {
	// Only accept HTTP POST requests for JSON-RPC
	if r.Method != http.MethodPost {
		// Return an error if the request method is not POST
		http.Error(w, "JSON-RPC server only accepts POST requests", http.StatusMethodNotAllowed)
		return
	}

	// Check if the response writer supports hijacking (needed for raw socket control)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		// If hijacking is not supported, return an internal error
		http.Error(w, "Server does not support connection hijacking", http.StatusInternalServerError)
		return
	}

	// Hijack the connection to gain control over it for raw communication
	conn, _, err := hijacker.Hijack()
	if err != nil {
		// Return an error if hijacking the connection fails
		http.Error(w, "Failed to hijack connection: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Log the new incoming connection for monitoring
	log.Printf("New RPC connection: %s", conn.RemoteAddr())
	// Process the hijacked connection asynchronously for handling RPC requests
	go rpc.ServeConn(conn)
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
