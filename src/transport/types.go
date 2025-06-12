package transport

import (
	"crypto/tls"
	"net"
	"net/http"

	"github.com/gorilla/websocket"
	"github.com/sphinx-core/go/src/rpc"
	"github.com/sphinx-core/go/src/security"
)

// IPConfig represents IP configuration for a node.
type IPConfig struct {
	IP   string // IP address (e.g., "192.168.1.1")
	Port string // Port number (e.g., "8080")
}

// TCPServer handles TCP connections.
type TCPServer struct {
	address   string
	listener  net.Listener
	messageCh chan *security.Message
	tlsConfig *tls.Config
	rpcServer *rpc.Server
	handshake *security.Handshake
}

// WebSocketServer handles WebSocket connections.
type WebSocketServer struct {
	address   string
	mux       *http.ServeMux
	upgrader  websocket.Upgrader
	messageCh chan *security.Message
	tlsConfig *tls.Config
	rpcServer *rpc.Server
	handshake *security.Handshake
}
