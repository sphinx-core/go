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

package main

import (
	"fmt"
	"log"
	"net/http"

	rpc "github.com/sphinx-core/go/src/jrpc/rpc"
)

func main() {
	// Initialize the WebSocket server
	wsServer := rpc.NewWebSocketServer()

	// Register the WebSocket handler for the RPC endpoint
	http.HandleFunc("/rpc", wsServer.HandleWebSocketUpgrade) // WebSocket upgrade handler

	// Start the HTTP server on localhost:8080
	log.Println("Starting server on http://localhost:8080/rpc")
	go func() {
		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Fatalf("Server failed: %s", err)
		}
	}()

	client := &http.Client{}

	// Define the server URL for WebSocket (ws:// instead of http://)
	serverURL := "ws://localhost:8080/rpc" // WebSocket URL

	// Create a new WebSocket client codec
	clientCodec, err := rpc.NewClientCodecWebSocket(serverURL, client)
	if err != nil {
		log.Fatalf("Error creating client codec: %v", err)
	}

	// Prepare a request to call the example service method
	req := &rpc.Request{
		Seq:           1,
		ServiceMethod: "exampleServiceMethod",
	}

	// Call WriteRequest to send a WebSocket RPC request
	err = clientCodec.WriteRequest(req, "World")
	if err != nil {
		log.Fatalf("Error sending request: %v", err)
	}

	// Prepare a response object
	resp := &rpc.Response{}

	// Read the response header
	err = clientCodec.ReadResponseHeader(resp)
	if err != nil {
		log.Fatalf("Error reading response header: %v", err)
	}

	// Output the response details
	fmt.Printf("Response received: %v\n", resp)

	// Prepare a place to store the response body
	var result string
	err = clientCodec.ReadResponseBody(&result)
	if err != nil {
		log.Fatalf("Error reading response body: %v", err)
	}

	// Output the result
	fmt.Printf("Result: %s\n", result)

	// Close the clientCodec connection
	err = clientCodec.Close()
	if err != nil {
		log.Fatalf("Error closing client codec: %v", err)
	}
}
