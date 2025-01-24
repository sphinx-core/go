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
	"io"
	"net"
	"net/http"
	"net/rpc"
	"sync"
	"time"
)

// Error variable for handling missing parameters in the request body
var errMissingParams = errors.New("jsonrpc: request body missing params")

// Predefined null value for invalid requests
var null = json.RawMessage([]byte("null"))

// createHTTPClient creates and configures an HTTP client with connection pooling and timeouts.
func CreateHTTPClient() *http.Client { // Changed to uppercase 'C'
	transport := &http.Transport{
		MaxIdleConns:        100, // Maximum number of idle connections
		MaxIdleConnsPerHost: 50,  // Maximum number of idle connections per host
		IdleConnTimeout:     90 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second, // Timeout for establishing new connections
			KeepAlive: 30 * time.Second, // Keep-alive period for idle connections
		}).DialContext,
	}
	return &http.Client{Transport: transport}
}

// asyncCall allows asynchronous execution of RPC calls and returns a channel for response handling.
func AsyncCall(client *rpc.Client, serviceMethod string, args any) <-chan *rpc.Call { // Changed to uppercase 'A'
	done := make(chan *rpc.Call, 1)
	go func() {
		client.Go(serviceMethod, args, nil, done)
	}()
	return done
}

// =====================
// ServerCodec Implementation
// =====================

// serverCodec implements the rpc.ServerCodec interface for handling JSON-RPC requests and responses.
type serverCodec struct {
	dec *json.Decoder // Decoder for reading JSON values from the connection
	enc *json.Encoder // Encoder for writing JSON values to the connection
	c   io.Closer     // Closer for the connection

	req serverRequest // Temporary workspace for request data

	mutex   sync.Mutex                  // Mutex to protect access to seq and pending
	seq     uint64                      // Sequence number for each request
	pending map[uint64]*json.RawMessage // Maps sequence numbers to request IDs
}

// NewServerCodec creates a new rpc.ServerCodec for handling JSON-RPC.
func NewServerCodec(conn io.ReadWriteCloser) rpc.ServerCodec {
	return &serverCodec{
		dec:     json.NewDecoder(conn),
		enc:     json.NewEncoder(conn),
		c:       conn,
		pending: make(map[uint64]*json.RawMessage),
	}
}

// serverRequest represents the structure of a JSON-RPC request.
type serverRequest struct {
	Method string           `json:"method"` // Method name of the RPC request
	Params *json.RawMessage `json:"params"` // Parameters for the method
	Id     *json.RawMessage `json:"id"`     // Unique ID for the request
}

// reset resets the fields of the serverRequest for reuse.
func (r *serverRequest) reset() {
	r.Method = ""
	r.Params = nil
	r.Id = nil
}

// serverResponse represents the structure of a JSON-RPC response.
type serverResponse struct {
	Id     *json.RawMessage `json:"id"`     // ID from the original request
	Result any              `json:"result"` // Result of the RPC method call
	Error  any              `json:"error"`  // Error message if there is an error
}

// ReadRequestHeader reads the header of the incoming JSON-RPC request and populates the rpc.Request.
// The header contains information about the service method being called and the sequence number for the request.
// It also manages the sequence of requests to keep track of pending requests.
func (c *serverCodec) ReadRequestHeader(r *rpc.Request) error {
	// Reset the server request object to ensure it is ready for the next request
	c.req.reset()

	// Decode the JSON-RPC header into the server request struct
	if err := c.dec.Decode(&c.req); err != nil {
		// Return an error if decoding the request header fails
		return err
	}

	// Set the service method in the rpc.Request object from the decoded request
	r.ServiceMethod = c.req.Method

	// Lock the mutex to ensure thread safety while modifying the sequence and pending map
	c.mutex.Lock()
	// Increment the sequence number for the new request
	c.seq++
	// Store the request ID in the pending map, mapping the sequence number to the request ID
	c.pending[c.seq] = c.req.Id
	// Set the sequence number in the rpc.Request object
	r.Seq = c.seq
	// Unlock the mutex after modifying the sequence and pending map
	c.mutex.Unlock()

	// Return nil if the header is read and processed successfully
	return nil
}

// ReadRequestBody reads the body of the request and unmarshals the parameters into the provided value.
// The body contains the actual data for the method call (arguments to the method).
func (c *serverCodec) ReadRequestBody(x any) error {
	// If the provided value is nil, return without doing anything
	if x == nil {
		return nil
	}

	// If no parameters are present in the request, return an error indicating missing parameters
	if c.req.Params == nil {
		return errMissingParams
	}

	// Define a single-element array to hold the unmarshalled parameters
	var params [1]any
	// Assign the provided value to the parameters array (only one argument is expected)
	params[0] = x

	// Unmarshal the parameters from the JSON payload into the provided value (x)
	return json.Unmarshal(*c.req.Params, &params)
}

// WriteResponse encodes and writes the JSON-RPC response to the connection.
// The response contains either the result of the method call or an error message.
func (c *serverCodec) WriteResponse(r *rpc.Response, x any) error {
	// Lock the mutex to ensure thread safety while modifying the pending map
	c.mutex.Lock()
	// Retrieve the request ID associated with the sequence number in the response
	id, ok := c.pending[r.Seq]
	// Remove the entry from the pending map after using it
	delete(c.pending, r.Seq)
	// Unlock the mutex after modifying the pending map
	c.mutex.Unlock()

	// If no corresponding request ID was found, return an error
	if !ok {
		return errors.New("invalid sequence number in response")
	}

	// If the request ID is nil, assign the null value (no ID) for the response
	if id == nil {
		id = &null
	}

	// Create a new serverResponse struct to hold the response data
	resp := serverResponse{Id: id}

	// If there is no error in the response, set the result; otherwise, set the error message
	if r.Error == "" {
		resp.Result = x
	} else {
		resp.Error = r.Error
	}

	// Encode the response into JSON and write it to the connection
	return c.enc.Encode(resp)
}

// Close closes the connection used by the serverCodec.
// This method is called to clean up the connection resources once the communication is complete.
func (c *serverCodec) Close() error {
	// Close the underlying connection and return any error that may occur
	return c.c.Close()
}

// ServeConn serves the JSON-RPC server on a single connection.
// It reads incoming requests, processes them, and writes responses back to the client.
func ServeConn(conn io.ReadWriteCloser) {
	// Create a new server codec for the connection and serve it using the rpc package
	rpc.ServeCodec(NewServerCodec(conn))
}

// HandleRPC serves JSON-RPC requests over HTTP connections.
// It expects HTTP POST requests containing JSON-RPC data and handles the connection accordingly.
func HandleRPC(w http.ResponseWriter, r *http.Request) {
	// Only accept HTTP POST requests for JSON-RPC
	if r.Method != http.MethodPost {
		// Respond with an error if the method is not POST
		http.Error(w, "JSON-RPC server only accepts POST requests", http.StatusMethodNotAllowed)
		return
	}

	// Check if the response writer supports hijacking (necessary for establishing custom connections)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		// If hijacking is not supported, respond with an error
		http.Error(w, "Server does not support connection hijacking", http.StatusInternalServerError)
		return
	}

	// Hijack the connection to gain control over the network connection
	conn, _, err := hijacker.Hijack()
	if err != nil {
		// If hijacking fails, respond with an error and the reason
		http.Error(w, "Failed to hijack connection: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Serve the hijacked connection by processing JSON-RPC requests asynchronously
	go rpc.ServeConn(conn)
}
