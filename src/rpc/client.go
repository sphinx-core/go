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
	"fmt"
	"io"
	"net"
	"net/rpc"
	"sync"
)

// clientCodec implements the rpc.ClientCodec interface for handling JSON-RPC requests and responses.
type clientCodec struct {
	dec *json.Decoder // Decoder for reading JSON values from the connection
	enc *json.Encoder // Encoder for writing JSON values to the connection
	c   io.Closer     // Closer for the connection

	// Temporary workspace for request and response data
	req  clientRequest  // Struct to hold the client request
	resp clientResponse // Struct to hold the client response

	// Synchronization for pending requests
	mutex   sync.Mutex        // Mutex to protect access to the pending map
	pending map[uint64]string // Map that stores request IDs and their corresponding service methods
}

// NewClientCodec creates a new clientCodec, which will use JSON-RPC over the given connection.
func NewClientCodec(conn io.ReadWriteCloser) rpc.ClientCodec {
	return &clientCodec{
		dec:     json.NewDecoder(conn),   // Create a new JSON decoder
		enc:     json.NewEncoder(conn),   // Create a new JSON encoder
		c:       conn,                    // Store the connection object
		pending: make(map[uint64]string), // Initialize the pending map to track requests
	}
}

// clientRequest represents the structure of a JSON-RPC request.
type clientRequest struct {
	Method string `json:"method"` // Name of the method to be called
	Params [1]any `json:"params"` // Parameters for the method
	Id     uint64 `json:"id"`     // Unique identifier for the request
}

// WriteRequest encodes and writes a JSON-RPC request to the connection.
func (c *clientCodec) WriteRequest(r *rpc.Request, param any) error {
	// Lock the mutex to safely modify the pending map
	c.mutex.Lock()
	c.pending[r.Seq] = r.ServiceMethod // Store the service method for the request ID
	c.mutex.Unlock()

	// Set the fields of the client request struct
	c.req.Method = r.ServiceMethod
	c.req.Params[0] = param
	c.req.Id = r.Seq

	// Encode and write the request to the connection
	return c.enc.Encode(&c.req)
}

// clientResponse represents the structure of a JSON-RPC response.
type clientResponse struct {
	Id     uint64           `json:"id"`     // Unique identifier for the response
	Result *json.RawMessage `json:"result"` // The result of the method call
	Error  any              `json:"error"`  // Error message if any
}

// reset resets the client response object for reuse.
func (r *clientResponse) reset() {
	r.Id = 0
	r.Result = nil
	r.Error = nil
}

// ReadResponseHeader reads the response header from the connection and fills the rpc.Response.
func (c *clientCodec) ReadResponseHeader(r *rpc.Response) error {
	// Reset the response before reading new data
	c.resp.reset()

	// Decode the response from the connection
	if err := c.dec.Decode(&c.resp); err != nil {
		return err // Return error if decoding fails
	}

	// Lock the mutex to safely access the pending map
	c.mutex.Lock()
	// Set the service method from the pending map using the response ID
	r.ServiceMethod = c.pending[c.resp.Id]
	// Remove the request ID from the pending map
	delete(c.pending, c.resp.Id)
	c.mutex.Unlock()

	// Set the response ID and initialize error field
	r.Error = ""
	r.Seq = c.resp.Id

	// Check if the response contains an error or no result
	if c.resp.Error != nil || c.resp.Result == nil {
		// Convert the error to a string if it's not already
		x, ok := c.resp.Error.(string)
		if !ok {
			return fmt.Errorf("invalid error %v", c.resp.Error) // Invalid error format
		}
		if x == "" {
			x = "unspecified error" // Default error message if it's empty
		}
		r.Error = x // Set the error message in the rpc response
	}
	return nil
}

// ReadResponseBody reads the body of the response and unmarshals it into the provided result.
func (c *clientCodec) ReadResponseBody(x any) error {
	if x == nil {
		return nil // No response body to read if nil
	}
	// Unmarshal the result into the provided object
	return json.Unmarshal(*c.resp.Result, x)
}

// Close closes the connection used by the clientCodec.
func (c *clientCodec) Close() error {
	return c.c.Close() // Close the underlying connection
}

// NewClient creates and returns a new rpc.Client with the provided connection.
func NewClient(conn io.ReadWriteCloser) *rpc.Client {
	return rpc.NewClientWithCodec(NewClientCodec(conn))
}

// Dial establishes a connection to a JSON-RPC server at the specified network and address.
func Dial(network, address string) (*rpc.Client, error) {
	// Dial the server using the provided network type and address
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err // Return error if the connection fails
	}
	// Return a new client with the established connection
	return NewClient(conn), err
}
