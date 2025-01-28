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
	"fmt"
	"log"
	"net"
	"net/rpc"
)

// Define your RPC server structure that will handle incoming requests.
type RPCServer struct{}

// Define a struct for the arguments, typically used as input for RPC methods.
type Args struct {
	X, Y int // The two integers that will be used in the RPC method for calculation.
}

// Define a struct for the result, which will hold the output of the RPC method.
type Result struct {
	Sum int // The sum of the two integers, to be returned as the result of the RPC method.
}

// Call performs an RPC call using the provided codec, method, arguments, and result reference.
// It handles request encoding, response decoding, and error handling throughout the process.
func CallClient(codec Codec, method string, args any, result any) error {
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

// RPC method that calls the `Call` function internally
func (s *RPCServer) Add(args *Args, result *Result) error {
	// Perform the addition operation using the Args values.
	result.Sum = args.X + args.Y

	// If any error occurs, return it, but in this case, there's no specific error to handle.
	return nil
}

// StartServer starts the RPC server and listens on a given address.
func CallServer(address string) error {
	// Register the RPCServer type with the Go RPC framework.
	// This tells the RPC server how to handle requests.
	server := new(RPCServer)    // Create a new instance of the RPCServer struct
	err := rpc.Register(server) // Register the server
	if err != nil {
		// Log a fatal error if registration fails and terminate the program
		log.Fatalf("Error registering RPC server: %v", err)
		return err // Return the error to stop further processing
	}

	// Start listening for incoming TCP connections on the provided address
	listener, err := net.Listen("tcp", address) // Start the listener on the given address
	if err != nil {
		// Log a fatal error if the server cannot listen on the address
		log.Fatalf("Error listening on address %s: %v", address, err)
		return err // Return the error to stop further processing
	}
	// Ensure the listener is closed when the function exits
	defer listener.Close()

	// Log that the server is now listening on the provided address
	log.Printf("RPC server listening on %s", address)

	// Accept incoming connections continuously
	for {
		// Accept a new incoming connection from the listener
		conn, err := listener.Accept() // Wait for a new connection
		if err != nil {
			// Log an error and continue accepting new connections in case of failure
			log.Printf("Error accepting connection: %v", err)
			continue // Continue the loop, so the server remains running
		}

		// Handle the accepted connection concurrently using goroutines
		// This allows the server to handle multiple connections simultaneously
		go rpc.ServeConn(conn) // Serve the connection using the RPC server
	}
}
