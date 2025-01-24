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
	"net/http"
	"net/rpc"
	"sync"
)

// Error variable for handling missing parameters in the request body
var errMissingParams = errors.New("jsonrpc: request body missing params")

// Predefined null value for invalid requests
var null = json.RawMessage([]byte("null"))

// serverCodec implements the rpc.ServerCodec interface for handling JSON-RPC requests and responses.
type serverCodec struct {
	dec *json.Decoder // Decoder for reading JSON values from the connection
	enc *json.Encoder // Encoder for writing JSON values to the connection
	c   io.Closer     // Closer for the connection

	// Temporary workspace for request data
	req serverRequest

	// The sequence number (seq) is used to uniquely identify each request.
	// We assign uint64 sequence numbers to incoming requests but save the
	// original request ID (which can be any JSON value) in the pending map.
	// When rpc responds, we use the sequence number in the response to
	// find the original request ID.
	mutex   sync.Mutex                  // Mutex to protect access to seq and pending
	seq     uint64                      // Sequence number for each request
	pending map[uint64]*json.RawMessage // Maps sequence numbers to request IDs
}

// NewServerCodec returns a new rpc.ServerCodec for handling JSON-RPC on the provided connection.
func NewServerCodec(conn io.ReadWriteCloser) rpc.ServerCodec {
	return &serverCodec{
		dec:     json.NewDecoder(conn),             // Create a new JSON decoder for reading from the connection
		enc:     json.NewEncoder(conn),             // Create a new JSON encoder for writing to the connection
		c:       conn,                              // Store the connection object
		pending: make(map[uint64]*json.RawMessage), // Initialize the pending map
	}
}

// serverRequest represents the structure of a JSON-RPC request.
type serverRequest struct {
	Method string           `json:"method"` // Method name of the RPC request
	Params *json.RawMessage `json:"params"` // Parameters for the method (may be null or any JSON value)
	Id     *json.RawMessage `json:"id"`     // Unique ID for the request (can be any JSON value)
}

// reset resets the fields of the serverRequest for reuse.
func (r *serverRequest) reset() {
	r.Method = ""
	r.Params = nil
	r.Id = nil
}

// serverResponse represents the structure of a JSON-RPC response.
type serverResponse struct {
	Id     *json.RawMessage `json:"id"`     // ID from the original request (can be null if invalid)
	Result any              `json:"result"` // Result of the RPC method call
	Error  any              `json:"error"`  // Error message if there is an error in processing the request
}

// ReadRequestHeader reads the header of the incoming JSON-RPC request and populates the rpc.Request.
func (c *serverCodec) ReadRequestHeader(r *rpc.Request) error {
	// Reset the request struct to clear any previous data
	c.req.reset()

	// Decode the incoming JSON request into the serverRequest struct
	if err := c.dec.Decode(&c.req); err != nil {
		return err // Return error if decoding fails
	}

	// Set the ServiceMethod for the RPC request
	r.ServiceMethod = c.req.Method

	// The JSON request ID can be any JSON value. RPC expects a uint64 ID.
	// We assign a sequence number and save the original request ID in the pending map.
	c.mutex.Lock()
	c.seq++                     // Increment the sequence number for each new request
	c.pending[c.seq] = c.req.Id // Store the original request ID
	c.req.Id = nil              // Remove the request ID from the JSON-RPC request
	r.Seq = c.seq               // Set the sequence number in the rpc.Request
	c.mutex.Unlock()

	return nil
}

// ReadRequestBody reads the body of the request and unmarshals the parameters into the provided value.
func (c *serverCodec) ReadRequestBody(x any) error {
	if x == nil {
		return nil // No body to read if x is nil
	}
	// If no parameters are provided in the request, return an error
	if c.req.Params == nil {
		return errMissingParams
	}
	// JSON params are expected to be an array value; RPC params are usually structs.
	// We unmarshal the JSON params into an array containing a struct for now.
	var params [1]any
	params[0] = x
	return json.Unmarshal(*c.req.Params, &params) // Unmarshal the parameters into the struct
}

// WriteResponse encodes and writes the JSON-RPC response to the connection.
func (c *serverCodec) WriteResponse(r *rpc.Response, x any) error {
	// Lock the mutex to safely access and modify the pending map
	c.mutex.Lock()
	b, ok := c.pending[r.Seq] // Get the original request ID for the sequence number
	if !ok {
		// If the sequence number is invalid, unlock and return an error
		c.mutex.Unlock()
		return errors.New("invalid sequence number in response")
	}
	// Remove the sequence number from the pending map after processing
	delete(c.pending, r.Seq)
	c.mutex.Unlock()

	// If the request ID is nil (invalid request), use JSON null for the response ID
	if b == nil {
		b = &null
	}

	// Create the response object
	resp := serverResponse{Id: b}
	if r.Error == "" {
		resp.Result = x // Set the result if there is no error
	} else {
		resp.Error = r.Error // Set the error message if there is an error
	}

	// Encode the response and send it to the client
	return c.enc.Encode(resp)
}

// Close closes the connection used by the serverCodec.
func (c *serverCodec) Close() error {
	return c.c.Close() // Close the underlying connection
}

// ServeConn serves the JSON-RPC server on a single connection. This blocks until the client disconnects.
func ServeConn(conn io.ReadWriteCloser) {
	// Use the rpc.ServeCodec function to serve the connection using the serverCodec
	rpc.ServeCodec(NewServerCodec(conn))
}

// HandleRPC wraps the JSON-RPC server logic with an HTTP handler
func HandleRPC(w http.ResponseWriter, r *http.Request) {
	// Ensure the request method is POST
	if r.Method != http.MethodPost {
		http.Error(w, "JSON-RPC server only accepts POST requests", http.StatusMethodNotAllowed)
		return
	}

	// Hijack the HTTP connection to use it for RPC communication
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Server does not support connection hijacking", http.StatusInternalServerError)
		return
	}

	// Hijack the connection
	conn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Failed to hijack connection: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Serve JSON-RPC on the hijacked connection
	go rpc.ServeConn(conn)
}
