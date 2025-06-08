// MIT License
//
// Copyright (c) 2024 sphinx-core
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

package main

import (
	"crypto/tls"
	"flag"
	"log"

	"github.com/sphinx-core/go/src/core"
	"github.com/sphinx-core/go/src/http"
	"github.com/sphinx-core/go/src/p2p"
	"github.com/sphinx-core/go/src/rpc"
	"github.com/sphinx-core/go/src/security"
	"github.com/sphinx-core/go/src/transport"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:30303", "TCP server address")
	httpAddr := flag.String("httpaddr", "127.0.0.1:8545", "HTTP server address")
	wsAddr := flag.String("wsaddr", "127.0.0.1:8546", "WebSocket server address")
	seeds := flag.String("seeds", "", "Comma-separated list of seed nodes")
	flag.Parse()

	// Load TLS certificate
	cert, err := tls.LoadX509KeyPair("cert.pem", "cert.pem")
	if err != nil {
		log.Fatalf("Failed to load TLS certificate: %v", err)
	}
	tlsConfig := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		CurvePreferences: []tls.CurveID{tls.X25519},
		MinVersion:       tls.VersionTLS13,
	}

	// Initialize shared blockchain and message channel
	blockchain := core.NewBlockchain()
	messageCh := make(chan *security.Message, 100)

	// Initialize RPC server with shared blockchain
	rpcServer := rpc.NewServer(messageCh, blockchain)

	// Start TCP server
	tcpServer := transport.NewTCPServer(*addr, messageCh, tlsConfig, rpcServer)
	go func() {
		if err := tcpServer.Start(); err != nil {
			log.Fatalf("TCP server failed: %v", err)
		}
	}()

	// Start HTTP server
	httpServer := http.NewServer(*httpAddr, messageCh, blockchain)
	go func() {
		if err := httpServer.Start(); err != nil {
			log.Fatalf("HTTP server failed: %v", err)
		}
	}()

	// Start WebSocket server
	wsServer := transport.NewWebSocketServer(*wsAddr, messageCh, tlsConfig, rpcServer)
	go func() {
		if err := wsServer.Start(); err != nil {
			log.Fatalf("WebSocket server failed: %v", err)
		}
	}()

	// Start P2P server
	p2pServer := p2p.NewServer(*addr, []string{*seeds}, blockchain)
	if err := p2pServer.Start(); err != nil {
		log.Fatalf("P2P server failed: %v", err)
	}

	// Keep the main goroutine running
	select {}
}
