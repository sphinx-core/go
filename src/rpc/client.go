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
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	paramsJSON, _ := json.Marshal(params)
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  string(paramsJSON),
		ID:      1,
	}
	msg := &security.Message{Type: "jsonrpc", Data: req}
	data, err := msg.Encode()
	if err != nil {
		return nil, err
	}

	if _, err := conn.Write(data); err != nil {
		return nil, err
	}

	respData := readConn(conn)
	var resp JSONRPCResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// readConn reads data from a connection.
func readConn(conn net.Conn) []byte {
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	return buf[:n]
}
