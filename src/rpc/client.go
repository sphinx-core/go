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
	"time"

	security "github.com/sphinx-core/go/src/handshake"
)

// CallRPC sends an RPC request to a peer, supporting both JSON and binary formats.
func CallRPC(address, method string, params interface{}, nodeID NodeID, ttl uint16) (*Message, error) {
	conn, err := net.Dial("udp", address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Convert method to RPCType
	var rpcType RPCType
	switch method {
	case "getblockcount":
		rpcType = RPCGetBlockCount
	case "getbestblockhash":
		rpcType = RPCGetBestBlockHash
	case "getblock":
		rpcType = RPCGetBlock
	case "getblocks":
		rpcType = RPCGetBlocks
	case "sendrawtransaction":
		rpcType = RPCSendRawTransaction
	case "gettransaction":
		rpcType = RPCGetTransaction
	default:
		return nil, ErrUnsupportedRPCType
	}

	// Serialize params
	paramsData, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}

	// Create Message
	msg := &Message{
		RPCType: rpcType,
		Query:   true,
		TTL:     ttl,
		Target:  NodeID{}, // Set to target node ID in production
		RPCID:   RPCID(time.Now().UnixNano()),
		From: Remote{
			NodeID:  nodeID,
			Address: net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0}, // Set actual address in production
		},
		Values:    [][]byte{paramsData},
		Iteration: 0,
		Secret:    uint16(time.Now().UnixNano() % 65536),
	}

	// Serialize Message
	data, err := msg.Marshal(make([]byte, msg.MarshalSize()))
	if err != nil {
		return nil, err
	}

	// Wrap in security.Message
	secMsg := &security.Message{Type: "rpc", Data: data}
	encodedData, err := secMsg.Encode()
	if err != nil {
		return nil, err
	}

	if _, err := conn.Write(encodedData); err != nil {
		return nil, err
	}

	// Read response
	respData := readConn(conn)
	respMsg, err := security.DecodeMessage(respData)
	if err != nil {
		return nil, err
	}

	// Ensure the response is of type "rpc"
	if respMsg.Type != "rpc" {
		return nil, ErrInvalidMessageFormat
	}

	// Extract and deserialize the RPC Message
	dataBytes, ok := respMsg.Data.([]byte)
	if !ok {
		return nil, ErrInvalidMessageFormat
	}

	var resp Message
	if err := resp.Unmarshal(dataBytes); err != nil {
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
