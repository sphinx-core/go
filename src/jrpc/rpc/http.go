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
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

// clientCodecHTTP implements a custom JSON-RPC client codec for handling JSON-RPC requests and responses over HTTP.
type clientCodecHTTP struct {
	dec     *json.Decoder     // Decoder for reading JSON values from the HTTP response
	client  *http.Client      // HTTP client to make requests
	url     string            // The URL of the JSON-RPC server
	req     clientRequest     // Request structure for JSON-RPC
	resp    clientResponse    // Response structure for JSON-RPC
	mutex   sync.Mutex        // Mutex to protect access to the pending map
	pending map[uint64]string // Map that stores request IDs and their corresponding service methods
}

// Request represents a custom structure for an RPC request.
type Request struct {
	Seq           uint64 // Sequence ID for the request
	ServiceMethod string // The method being called
}

// Response represents a custom structure for an RPC response.
type Response struct {
	Seq           uint64 // Sequence ID for the response
	ServiceMethod string // The method being called
	Error         string // Error message if any
}

// NewClientCodecHTTP creates a new clientCodecHTTP, which will use JSON-RPC over HTTP for the given URL.
func NewClientCodecHTTP(url string, client *http.Client) *clientCodecHTTP {
	return &clientCodecHTTP{
		dec:     json.NewDecoder(nil),    // Decoder (to be used later)
		client:  client,                  // HTTP client for making requests
		url:     url,                     // URL of the JSON-RPC server
		pending: make(map[uint64]string), // Initialize the pending map to track requests
	}
}

// WriteRequest encodes and sends a JSON-RPC request over HTTP.
func (c *clientCodecHTTP) WriteRequest(r *Request, param any) error {
	// Lock the mutex to safely modify the pending map
	c.mutex.Lock()
	c.pending[r.Seq] = r.ServiceMethod // Store the service method for the request ID
	c.mutex.Unlock()

	// Set the fields of the client request struct
	c.req.Method = r.ServiceMethod // Assign the service method to the request
	c.req.Params[0] = param        // Assign the parameter to the request
	c.req.Id = r.Seq               // Assign the sequence ID to the request

	// Encode the request into JSON and prepare an HTTP POST request
	body, err := json.Marshal(&c.req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err) // Handle marshaling error
	}
	req, err := http.NewRequest("POST", c.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err) // Handle HTTP request creation error
	}
	req.Header.Set("Content-Type", "application/json") // Set the appropriate content type

	// Send the HTTP request using the HTTP client
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send HTTP request: %w", err) // Handle HTTP request error
	}
	defer resp.Body.Close() // Ensure the response body is closed after processing

	// Initialize the JSON decoder for the response body
	c.dec = json.NewDecoder(resp.Body) // Assign the decoder to the response body
	return nil                         // Return nil if the request was successful
}

// ReadResponseHeader reads the response header from the HTTP response and fills the custom Response structure.
func (c *clientCodecHTTP) ReadResponseHeader(r *Response) error {
	// Reset the response before reading new data
	c.resp.reset()

	// Decode the response from the HTTP response body
	if err := c.dec.Decode(&c.resp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
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
		r.Error = x // Set the error message in the response
	}
	return nil
}

// ReadResponseBody reads the body of the response and unmarshals it into the provided result.
func (c *clientCodecHTTP) ReadResponseBody(x any) error {
	if x == nil {
		return nil // No response body to read if nil
	}
	// Unmarshal the result into the provided object
	return json.Unmarshal(*c.resp.Result, x)
}

// Close closes the HTTP connection. In this case, it's handled by the HTTP client.
func (c *clientCodecHTTP) Close() error {
	// HTTP connections are managed by the client
	return nil
}
