// server/server.go
package server

import (
	"crypto/tls"

	"github.com/yourusername/myblockchain/http"
	"github.com/yourusername/myblockchain/security"
	"github.com/yourusername/myblockchain/transport"
)

// Server manages all protocol servers.
type Server struct {
	tcpServer  *transport.TCPServer
	wsServer   *transport.WebSocketServer
	httpServer *http.Server
}

// NewServer creates a new server.
func NewServer(tcpAddr, wsAddr, httpAddr string, tlsConfig *tls.Config) *Server {
	messageCh := make(chan *security.Message)
	return &Server{
		tcpServer:  transport.NewTCPServer(tcpAddr, messageCh, tlsConfig),
		wsServer:   transport.NewWebSocketServer(wsAddr, messageCh, tlsConfig),
		httpServer: http.NewServer(httpAddr, messageCh),
	}
}

// Start runs all servers.
func (s *Server) Start() error {
	go s.tcpServer.Start()
	go s.httpServer.Start()
	return s.wsServer.Start()
}
