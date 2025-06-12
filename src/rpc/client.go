// MIT License
//
// # Copyright (c) 2024 sphinx-core
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
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// go/src/rpc/client.go
package rpc

import (
	"encoding/json"
	"net"

	"github.com/sphinx-core/go/src/security"
)

// CallRPC sends a JSON-RPC request to a peer.
func CallRPC(address, method string, params interface{}) (*JSONRPCResponse, error) {
	conn, err := net.Dial("tcp", address) // Establish a TCP connection to the given address
	if err != nil {                       // Check for connection error
		return nil, err // Return error if connection fails
	}
	defer conn.Close() // Ensure connection is closed when function returns

	paramsJSON, _ := json.Marshal(params) // Serialize params into JSON format, ignoring marshal error
	req := JSONRPCRequest{                // Create a JSON-RPC request struct
		JSONRPC: "2.0",              // JSON-RPC version
		Method:  method,             // RPC method to call
		Params:  string(paramsJSON), // Parameters as JSON string
		ID:      1,                  // Request ID (fixed as 1 here)
	}
	msg := &security.Message{Type: "jsonrpc", Data: req} // Wrap the JSON-RPC request inside a secure Message
	data, err := msg.Encode()                            // Encode the Message into bytes for sending
	if err != nil {                                      // Check encoding error
		return nil, err // Return error if encoding fails
	}

	if _, err := conn.Write(data); err != nil { // Write encoded bytes to the TCP connection
		return nil, err // Return error if writing fails
	}

	respData := readConn(conn)                              // Read response data from the connection
	var resp JSONRPCResponse                                // Prepare a variable to hold the unmarshaled response
	if err := json.Unmarshal(respData, &resp); err != nil { // Unmarshal JSON response into resp struct
		return nil, err // Return error if unmarshaling fails
	}

	return &resp, nil // Return the JSONRPCResponse pointer and no error
}

// readConn reads data from a connection.
func readConn(conn net.Conn) []byte {
	buf := make([]byte, 4096) // Create a buffer to hold read bytes, max size 4096 bytes
	n, _ := conn.Read(buf)    // Read data from connection into buffer, ignoring read error
	return buf[:n]            // Return only the bytes actually read
}
