// rpc/client.go
package rpc

import (
	"encoding/json"
	"net"

	"github.com/yourusername/myblockchain/security"
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
