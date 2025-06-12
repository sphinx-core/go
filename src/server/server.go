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

// go/src/server/server.go
package server

import (
	"crypto/tls"
	"log"
	"strings"

	"github.com/sphinx-core/go/src/core"
	"github.com/sphinx-core/go/src/http"
	"github.com/sphinx-core/go/src/p2p"
	"github.com/sphinx-core/go/src/rpc"
	"github.com/sphinx-core/go/src/security"
	"github.com/sphinx-core/go/src/transport"
)

// NewServer creates a new server.
func NewServer(tcpAddr, wsAddr, httpAddr, p2pAddr string, seeds []string, tlsConfig *tls.Config) *Server {
	messageCh := make(chan *security.Message, 100)
	blockchain := core.NewBlockchain()
	rpcServer := rpc.NewServer(messageCh, blockchain)

	// Parse p2pAddr into IP and port
	parts := strings.Split(p2pAddr, ":")
	if len(parts) != 2 {
		log.Fatalf("Invalid p2pAddr format: %s, expected IP:port", p2pAddr)
	}
	ip, port := parts[0], parts[1]

	return &Server{
		tcpServer:  transport.NewTCPServer(tcpAddr, messageCh, tlsConfig, rpcServer),
		wsServer:   transport.NewWebSocketServer(wsAddr, messageCh, tlsConfig, rpcServer),
		httpServer: http.NewServer(httpAddr, messageCh, blockchain),
		p2pServer:  p2p.NewServer(p2pAddr, ip, port, seeds, blockchain),
	}
}

// Start runs all servers.
func (s *Server) Start() error {
	go func() {
		if err := s.tcpServer.Start(); err != nil {
			log.Fatalf("TCP server failed: %v", err)
		}
	}()
	go func() {
		if err := s.httpServer.Start(); err != nil {
			log.Fatalf("HTTP server failed: %v", err)
		}
	}()
	go func() {
		if err := s.p2pServer.Start(); err != nil {
			log.Fatalf("P2P server failed: %v", err)
		}
	}()
	return s.wsServer.Start() // Run WebSocket server in the main goroutine
}
