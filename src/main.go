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
	"encoding/hex"
	"flag"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/sphinx-core/go/src/core"
	types "github.com/sphinx-core/go/src/core/transaction"
	"github.com/sphinx-core/go/src/http"
	logger "github.com/sphinx-core/go/src/log"
	"github.com/sphinx-core/go/src/network"
	"github.com/sphinx-core/go/src/p2p"
	"github.com/sphinx-core/go/src/rpc"
	"github.com/sphinx-core/go/src/security"
	"github.com/sphinx-core/go/src/transport"
)

func main() {
	// Initialize the custom logger for structured log output
	logger.Init()

	// Define CLI flags for addresses of the three nodes and HTTP API
	addrAlice := flag.String("addrAlice", "127.0.0.1:30303", "TCP server address for Alice")
	addrBob := flag.String("addrBob", "127.0.0.1:30304", "TCP server address for Bob")
	addrCharlie := flag.String("addrCharlie", "127.0.0.1:30305", "TCP server address for Charlie")
	httpAddr := flag.String("httpAddr", "127.0.0.1:8545", "HTTP server address for Alice")
	seeds := flag.String("seeds", "127.0.0.1:30304,127.0.0.1:30305", "Comma-separated list of seed nodes")
	flag.Parse()

	// Load TLS certificate for secure communication (self-signed in this example)
	cert, err := tls.LoadX509KeyPair("cert.pem", "cert.pem")
	if err != nil {
		logger.Fatalf("Failed to load TLS certificate: %v", err)
	}
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		CurvePreferences:   []tls.CurveID{tls.X25519},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // Skip verification for demo purposes
	}

	// Used to wait for all goroutines to complete before exiting
	var wg sync.WaitGroup

	// Channel to track readiness of TCP, HTTP, WS, and P2P servers
	readyCh := make(chan struct{}, 3*4) // 3 nodes × 4 services each

	// Define each node with its role and associated ports
	nodes := []struct {
		addr     string
		role     network.NodeRole
		name     string
		httpPort string
		wsPort   string
	}{
		{*addrAlice, network.RoleSender, "Alice", *httpAddr, "127.0.0.1:8546"},
		{*addrBob, network.RoleReceiver, "Bob", "127.0.0.1:8547", "127.0.0.1:8548"},
		{*addrCharlie, network.RoleValidator, "Charlie", "127.0.0.1:8549", "127.0.0.1:8550"},
	}

	// Split seed node addresses for P2P network
	seedList := strings.Split(*seeds, ",")

	// Prepare containers for message channels and P2P servers
	messageChans := make([]chan *security.Message, len(nodes))
	p2pServers := make([]*p2p.Server, len(nodes))
	publicKeys := make(map[string]string) // Used to check for duplicate keys

	for i, node := range nodes {
		// Validate IP address and port
		parts := strings.Split(node.addr, ":")
		if len(parts) != 2 {
			logger.Fatalf("Invalid address format for %s: %s", node.name, node.addr)
		}
		ip, port := parts[0], parts[1]
		if err := transport.ValidateIP(ip, port); err != nil {
			logger.Fatalf("Invalid IP or port for %s: %v", node.name, err)
		}

		// Initialize blockchain state for the node
		logger.Infof("Initializing blockchain for %s", node.name)
		blockchain := core.NewBlockchain()
		logger.Infof("Genesis block created for %s, hash: %x", node.name, blockchain.GetBestBlockHash())

		// Create a secure channel for RPC messages
		messageChans[i] = make(chan *security.Message, 100)
		rpcServer := rpc.NewServer(messageChans[i], blockchain)

		// Start TCP transport server
		tcpServer := transport.NewTCPServer(node.addr, messageChans[i], tlsConfig, rpcServer)
		wg.Add(1)
		go func(name, addr string) {
			defer wg.Done()
			logger.Infof("Starting TCP server for %s on %s", name, addr)
			if err := tcpServer.Start(); err != nil {
				logger.Errorf("TCP server failed for %s: %v", name, err)
			} else {
				readyCh <- struct{}{}
			}
		}(node.name, node.addr)

		// Start HTTP server for REST API
		httpServer := http.NewServer(node.httpPort, messageChans[i], blockchain)
		wg.Add(1)
		go func(name, port string) {
			defer wg.Done()
			logger.Infof("Starting HTTP server for %s on %s", name, port)
			if err := httpServer.Start(); err != nil {
				logger.Errorf("HTTP server failed for %s: %v", name, err)
			} else {
				readyCh <- struct{}{}
			}
		}(node.name, node.httpPort)

		// Start WebSocket server for real-time messaging
		wsServer := transport.NewWebSocketServer(node.wsPort, messageChans[i], tlsConfig, rpcServer)
		wg.Add(1)
		go func(name, port string) {
			defer wg.Done()
			logger.Infof("Starting WebSocket server for %s on %s", name, port)
			if err := wsServer.Start(); err != nil {
				logger.Errorf("WebSocket server failed for %s: %v", name, err)
			} else {
				readyCh <- struct{}{}
			}
		}(node.name, node.wsPort)

		// Start P2P server for decentralized messaging
		p2pServers[i] = p2p.NewServer(node.addr, ip, port, seedList, blockchain)
		wg.Add(1)
		go func(name string, server *p2p.Server) {
			defer wg.Done()
			logger.Infof("Starting P2P server for %s on %s", name, server.LocalNode().Address)
			if err := server.Start(); err != nil {
				logger.Errorf("P2P server failed for %s: %v", name, err)
			} else {
				readyCh <- struct{}{}
			}
		}(node.name, p2pServers[i])

		// Set node role and validate key integrity
		localNode := p2pServers[i].LocalNode()
		localNode.UpdateRole(node.role)
		logger.Infof("Node %s initialized with role %s", node.name, node.role)

		if len(localNode.PublicKey) == 0 || len(localNode.PrivateKey) == 0 {
			logger.Fatalf("Key generation failed for %s", node.name)
		}

		// Ensure uniqueness of public keys
		pubHex := hex.EncodeToString(localNode.PublicKey)
		logger.Infof("Node %s public key: %s", node.name, pubHex)

		if _, exists := publicKeys[pubHex]; exists {
			logger.Fatalf("Duplicate public key detected for %s: %s", node.name, pubHex)
		}
		publicKeys[pubHex] = node.name
	}

	// Wait until all TCP/HTTP/WS/P2P servers are up and running
	for i := 0; i < len(nodes)*4; i++ {
		<-readyCh
	}
	logger.Infof("All servers are ready")

	// Simulate a delay before submitting a transaction
	time.Sleep(5 * time.Second)

	// Create and submit a dummy transaction from Alice to Bob
	tx := &types.Transaction{
		Sender:    "127.0.0.1:30303",
		Receiver:  "127.0.0.1:30304",
		Amount:    big.NewInt(1000),  // Transfer amount
		GasLimit:  big.NewInt(21000), // Simplified gas limit
		GasPrice:  big.NewInt(1),     // Simplified gas price
		Timestamp: time.Now().Unix(), // Unix timestamp
		Nonce:     1,                 // Example nonce
	}

	logger.Infof("Submitting transaction from Alice to Bob: %+v", tx)
	err = http.SubmitTransaction(*httpAddr, *tx)
	if err != nil {
		logger.Errorf("Failed to submit transaction: %v", err)
	} else {
		logger.Infof("Transaction submitted successfully! Sender: %s, Receiver: %s, Amount: %s, Nonce: %d",
			tx.Sender, tx.Receiver, tx.Amount.String(), tx.Nonce)
	}

	// Periodically prune inactive peers from each node's peer list
	go func() {
		for {
			for _, server := range p2pServers {
				server.NodeManager().PruneInactivePeers(30 * time.Second)
			}
			time.Sleep(10 * time.Second)
		}
	}()

	// Prevent the program from exiting
	select {}
}
