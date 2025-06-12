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
	"log"
	"strings"

	"github.com/sphinx-core/go/src/core"
	"github.com/sphinx-core/go/src/http"
	"github.com/sphinx-core/go/src/p2p"
	"github.com/sphinx-core/go/src/rpc"
	"github.com/sphinx-core/go/src/security"
	"github.com/sphinx-core/go/src/transport"
)

// NewServer initializes and returns a new Server instance.
// It sets up TCP, WebSocket, HTTP, and P2P servers using the provided addresses and seed nodes.
func NewServer(tcpAddr, wsAddr, httpAddr, p2pAddr string, seeds []string) *Server {
	// Create a buffered channel to handle incoming secure messages.
	messageCh := make(chan *security.Message, 100)

	// Initialize the blockchain instance.
	blockchain := core.NewBlockchain()

	// Create an RPC server that can process messages and interact with the blockchain.
	rpcServer := rpc.NewServer(messageCh, blockchain)

	// Parse the P2P address string into IP and port parts.
	parts := strings.Split(p2pAddr, ":")
	if len(parts) != 2 {
		// If the address format is invalid, log the error and stop the application.
		log.Fatalf("Invalid p2pAddr format: %s, expected IP:port", p2pAddr)
	}
	ip, port := parts[0], parts[1]

	// Return a pointer to the initialized Server with all sub-servers configured.
	return &Server{
		tcpServer:  transport.NewTCPServer(tcpAddr, messageCh, rpcServer),      // Initialize TCP server with address, message channel, and RPC server.
		wsServer:   transport.NewWebSocketServer(wsAddr, messageCh, rpcServer), // Initialize WebSocket server similarly.
		httpServer: http.NewServer(httpAddr, messageCh, blockchain),            // Initialize HTTP server with blockchain and message handling.
		p2pServer:  p2p.NewServer(p2pAddr, ip, port, seeds, blockchain),        // Initialize P2P server using IP, port, seed peers, and blockchain.
	}
}

// Start launches all the server components (TCP, HTTP, P2P, WebSocket).
// It uses goroutines to run TCP, HTTP, and P2P servers concurrently.
// Only the WebSocket server blocks and returns an error if it fails.
func (s *Server) Start() error {
	go func() {
		// Start the TCP server in a separate goroutine.
		if err := s.tcpServer.Start(); err != nil {
			// If TCP server fails to start, log a fatal error and exit.
			log.Fatalf("TCP server failed: %v", err)
		}
	}()
	go func() {
		// Start the HTTP server concurrently.
		if err := s.httpServer.Start(); err != nil {
			// Log and terminate on HTTP server failure.
			log.Fatalf("HTTP server failed: %v", err)
		}
	}()
	go func() {
		// Start the P2P server in its own goroutine.
		if err := s.p2pServer.Start(); err != nil {
			// If P2P server cannot start, log a fatal error.
			log.Fatalf("P2P server failed: %v", err)
		}
	}()
	// Start the WebSocket server (blocking call).
	return s.wsServer.Start()
}
