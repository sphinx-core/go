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
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/sphinx-core/go/src/core"
	security "github.com/sphinx-core/go/src/handshake"
	"github.com/sphinx-core/go/src/http"
	"github.com/sphinx-core/go/src/network"
	"github.com/sphinx-core/go/src/p2p"
	"github.com/sphinx-core/go/src/rpc"
	"github.com/sphinx-core/go/src/transport"
	"github.com/syndtr/goleveldb/leveldb"
)

// serverRegistry holds running servers for shutdown.
var serverRegistry = struct {
	sync.Mutex
	servers map[string]*Server
}{
	servers: make(map[string]*Server),
}

// StoreServer stores a server instance by name.
func StoreServer(name string, srv *Server) {
	serverRegistry.Lock()
	defer serverRegistry.Unlock()
	serverRegistry.servers[name] = srv
}

// GetServer retrieves a server instance by name.
func GetServer(name string) *Server {
	serverRegistry.Lock()
	defer serverRegistry.Unlock()
	return serverRegistry.servers[name]
}

func NewServer(tcpAddr, wsAddr, httpAddr, p2pAddr string, seeds []string, db *leveldb.DB, readyCh chan struct{}, role network.NodeRole) *Server {
	messageCh := make(chan *security.Message, 100)

	// FIX: Pass all required parameters to NewBlockchain
	dataDir := fmt.Sprintf("data/blockchain-%s", strings.Replace(p2pAddr, ":", "-", -1))
	nodeID := fmt.Sprintf("node-%s", strings.Replace(p2pAddr, ":", "-", -1))

	// Create a list of validators (in a real scenario, this would come from config)
	validators := []string{nodeID} // Single validator for now

	// ADD NETWORK TYPE PARAMETER
	blockchain, err := core.NewBlockchain(dataDir, nodeID, validators, "devnet")
	if err != nil {
		log.Fatalf("Failed to create blockchain: %v", err)
	}

	rpcServer := rpc.NewServer(messageCh, blockchain)

	// Validate p2pAddr format and extract port
	parts := strings.Split(p2pAddr, ":")
	if len(parts) != 2 {
		log.Fatalf("Invalid p2pAddr format: %s, expected IP:port", p2pAddr)
	}
	udpPort := parts[1]

	// Create NodePortConfig for p2p.NewServer
	config := network.NodePortConfig{
		Name:      "Node-" + udpPort,
		TCPAddr:   tcpAddr,
		UDPPort:   udpPort,
		HTTPPort:  httpAddr,
		WSPort:    wsAddr,
		SeedNodes: seeds,
		Role:      role,
	}

	return &Server{
		tcpServer:  transport.NewTCPServer(tcpAddr, messageCh, rpcServer, readyCh),
		wsServer:   transport.NewWebSocketServer(wsAddr, messageCh, rpcServer),
		httpServer: http.NewServer(httpAddr, messageCh, blockchain, readyCh),
		p2pServer:  p2p.NewServer(config, blockchain, db),
		readyCh:    readyCh,
		nodeConfig: config,
	}
}

func (s *Server) Start() error {
	var errs []error
	var mu sync.Mutex

	// Start TCP server
	go func() {
		if err := s.tcpServer.Start(); err != nil {
			log.Printf("TCP server failed: %v", err)
			mu.Lock()
			errs = append(errs, fmt.Errorf("TCP server: %v", err))
			mu.Unlock()
		}
	}()

	// Start HTTP server
	go func() {
		if err := s.httpServer.Start(); err != nil {
			log.Printf("HTTP server failed: %v", err)
			mu.Lock()
			errs = append(errs, fmt.Errorf("HTTP server: %v", err))
			mu.Unlock()
		}
	}()

	// Start P2P server
	go func() {
		if err := s.p2pServer.Start(); err != nil {
			log.Printf("P2P server failed: %v", err)
			mu.Lock()
			errs = append(errs, fmt.Errorf("P2P server: %v", err))
			mu.Unlock()
		}
	}()

	// Start WebSocket server
	if err := s.wsServer.Start(s.readyCh); err != nil {
		log.Printf("WebSocket server failed: %v", err)
		mu.Lock()
		errs = append(errs, fmt.Errorf("WebSocket server: %v", err))
		mu.Unlock()
	}

	// Wait briefly to collect errors
	time.Sleep(1 * time.Second)
	mu.Lock()
	defer mu.Unlock()
	if len(errs) > 0 {
		return fmt.Errorf("errors starting servers: %v", errs)
	}
	return nil
}

func (s *Server) Close() error {
	var errs []error

	// Close P2P server
	if s.p2pServer != nil {
		if err := s.p2pServer.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close P2P server: %v", err))
		}
		if err := s.p2pServer.CloseDB(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close P2P DB: %v", err))
		}
	}

	// Close TCP server
	if s.tcpServer != nil {
		if err := s.tcpServer.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("failed to stop TCP server: %v", err))
		}
	}

	// Close HTTP server
	if s.httpServer != nil {
		if err := s.httpServer.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("failed to stop HTTP server: %v", err))
		}
	}

	// Close WebSocket server
	if s.wsServer != nil {
		if err := s.wsServer.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("failed to stop WebSocket server: %v", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors during server shutdown: %v", errs)
	}
	return nil
}

func (s *Server) TCPServer() *transport.TCPServer {
	return s.tcpServer
}

func (s *Server) WSServer() *transport.WebSocketServer {
	return s.wsServer
}

func (s *Server) HTTPServer() *http.Server {
	return s.httpServer
}

func (s *Server) P2PServer() *p2p.Server {
	return s.p2pServer
}
