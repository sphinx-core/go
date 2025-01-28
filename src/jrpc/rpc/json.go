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

import "fmt"

// Call performs an RPC call using the provided codec, method, arguments, and result reference.
// It handles request encoding, response decoding, and error handling throughout the process.
func Call(codec Codec, method string, args any, result any) error {
	// Initialize the request with a sequence ID and method name.
	req := &Request{
		Seq:           1,      // Example sequence ID (can be dynamic if multiple calls need tracking)
		ServiceMethod: method, // RPC method name to be invoked
	}
	resp := &Response{} // Prepare an empty response struct to populate with incoming data.

	// Encode and send the RPC request using the codec.
	if err := codec.WriteRequest(req, args); err != nil {
		// Return a wrapped error if the request encoding or sending fails.
		return fmt.Errorf("write request failed: %w", err)
	}

	// Read and decode the response header to verify the response status.
	if err := codec.ReadResponseHeader(resp); err != nil {
		// Return a wrapped error if reading the response header fails.
		return fmt.Errorf("read response header failed: %w", err)
	}

	// Check if the server returned an error in the response.
	if resp.Error != "" {
		// Return an error containing the server-side error message.
		return fmt.Errorf("rpc error: %s", resp.Error)
	}

	// Read and decode the response body into the provided result reference.
	if err := codec.ReadResponseBody(result); err != nil {
		// Return a wrapped error if reading the response body fails.
		return fmt.Errorf("read response body failed: %w", err)
	}

	// If all operations succeed, return nil to indicate a successful RPC call.
	return nil
}
