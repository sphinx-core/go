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
	blockchain := core.NewBlockchain()
	rpcServer := rpc.NewServer(messageCh, blockchain)

	// Validate p2pAddr format
	parts := strings.Split(p2pAddr, ":")
	if len(parts) != 2 {
		log.Fatalf("Invalid p2pAddr format: %s, expected IP:port", p2pAddr)
	}

	// Create NodePortConfig for p2p.NewServer
	config := network.NodePortConfig{
		Name:      "Node-" + parts[1], // Use port for unique name
		TCPAddr:   tcpAddr,            // Use tcpAddr instead of p2pAddr
		UDPPort:   p2pAddr,
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
		nodeConfig: config, // Store the NodePortConfig
	}
}

func (s *Server) Start() error {
	go func() {
		if err := s.tcpServer.Start(); err != nil {
			log.Printf("TCP server failed: %v", err)
		}
	}()
	go func() {
		if err := s.httpServer.Start(); err != nil {
			log.Printf("HTTP server failed: %v", err)
		}
	}()
	go func() {
		if err := s.p2pServer.Start(); err != nil {
			log.Printf("P2P server failed: %v", err)
		}
	}()
	return s.wsServer.Start(s.readyCh)
}

func (s *Server) Close() error {
	var errs []error
	if err := s.p2pServer.CloseDB(); err != nil {
		errs = append(errs, err)
	}
	if s.tcpServer != nil {
		if err := s.tcpServer.Stop(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.httpServer != nil {
		if err := s.httpServer.Stop(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.wsServer != nil {
		if err := s.wsServer.Stop(); err != nil {
			errs = append(errs, err)
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
