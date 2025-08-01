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

// go/src/transport/types.go
package transport

import (
	"net"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
	security "github.com/sphinx-core/go/src/handshake"
	"github.com/sphinx-core/go/src/rpc"
)

type IPConfig struct {
	IP   string
	Port string
}

// TCPServer represents a TCP server for handling P2P connections
type TCPServer struct {
	listener    net.Listener
	address     string
	messageCh   chan *security.Message
	rpcServer   *rpc.Server
	handshake   *security.Handshake
	tcpReadyCh  chan struct{}
	connections map[string]net.Conn                // Map of node address (e.g., 127.0.0.1:30307) to connection
	encKeys     map[string]*security.EncryptionKey // Map of node address to encryption key
	mu          sync.Mutex
}

// WebSocketServer manages WebSocket connections.
type WebSocketServer struct {
	address   string
	mux       *http.ServeMux
	server    *http.Server // Add server field to store http.Server
	upgrader  websocket.Upgrader
	messageCh chan *security.Message
	rpcServer *rpc.Server
	handshake *security.Handshake
}
