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
	"log"
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
	// Initialize log
	logger.Init()

	addrAlice := flag.String("addrAlice", "127.0.0.1:30303", "TCP server address for Alice")
	addrBob := flag.String("addrBob", "127.0.0.1:30304", "TCP server address for Bob")
	addrCharlie := flag.String("addrCharlie", "127.0.0.1:30305", "TCP server address for Charlie")
	httpAddr := flag.String("httpAddr", "127.0.0.1:8545", "HTTP server address for Alice")
	seeds := flag.String("seeds", "127.0.0.1:30304,127.0.0.1:30305", "Comma-separated list of seed nodes")
	flag.Parse()

	// Initialize TLS configuration
	cert, err := tls.LoadX509KeyPair("cert.pem", "cert.pem")
	if err != nil {
		log.Fatalf("Failed to load TLS certificate: %v", err)
	}
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		CurvePreferences:   []tls.CurveID{tls.X25519},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // For testing; set to false in production
	}

	// Wait group to manage server goroutines
	var wg sync.WaitGroup
	// Channel to signal server readiness
	readyCh := make(chan struct{}, len([]struct {
		addr     string
		role     network.NodeRole
		name     string
		httpPort string
		wsPort   string
	}{
		{*addrAlice, network.RoleSender, "Alice", *httpAddr, "127.0.0.1:8546"},
		{*addrBob, network.RoleReceiver, "Bob", "127.0.0.1:8547", "127.0.0.1:8548"},
		{*addrCharlie, network.RoleValidator, "Charlie", "127.0.0.1:8549", "127.0.0.1:8550"},
	}))

	// Start nodes for Alice, Bob, and Charlie
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

	seedList := strings.Split(*seeds, ",")
	messageChans := make([]chan *security.Message, len(nodes))
	p2pServers := make([]*p2p.Server, len(nodes))
	publicKeys := make(map[string]string)

	for i, node := range nodes {
		// Parse addr into IP and port
		parts := strings.Split(node.addr, ":")
		if len(parts) != 2 {
			log.Fatalf("Invalid address format for %s: %s, expected IP:port", node.name, node.addr)
		}
		ip, port := parts[0], parts[1]

		// Validate IP and port
		if err := transport.ValidateIP(ip, port); err != nil {
			log.Fatalf("Invalid IP or port for %s: %v", node.name, err)
		}

		// Initialize blockchain
		log.Printf("Initializing blockchain for %s", node.name)
		blockchain := core.NewBlockchain()
		log.Printf("Genesis block created for %s, hash: %x", node.name, blockchain.GetBestBlockHash())

		// Create message channel
		messageChans[i] = make(chan *security.Message, 100)

		// Initialize RPC server
		rpcServer := rpc.NewServer(messageChans[i], blockchain)

		// Start TCP server
		tcpServer := transport.NewTCPServer(node.addr, messageChans[i], tlsConfig, rpcServer)
		wg.Add(1)
		go func(name, addr string) {
			defer wg.Done()
			log.Printf("Starting TCP server for %s on %s", name, addr)
			if err := tcpServer.Start(); err != nil {
				log.Printf("TCP server failed for %s on %s: %v", name, addr, err)
			} else {
				log.Printf("TCP server started for %s on %s", name, addr)
				readyCh <- struct{}{}
			}
		}(node.name, node.addr)

		// Start HTTP server
		httpServer := http.NewServer(node.httpPort, messageChans[i], blockchain)
		wg.Add(1)
		go func(name, httpPort string) {
			defer wg.Done()
			log.Printf("Starting HTTP server for %s on %s", name, httpPort)
			if err := httpServer.Start(); err != nil {
				log.Printf("HTTP server failed for %s on %s: %v", name, httpPort, err)
			} else {
				log.Printf("HTTP server started for %s on %s", name, httpPort)
				readyCh <- struct{}{}
			}
		}(node.name, node.httpPort)

		// Start WebSocket server
		wsServer := transport.NewWebSocketServer(node.wsPort, messageChans[i], tlsConfig, rpcServer)
		wg.Add(1)
		go func(name, wsPort string) {
			defer wg.Done()
			log.Printf("Starting WebSocket server for %s on %s", name, wsPort)
			if err := wsServer.Start(); err != nil {
				log.Printf("WebSocket server failed for %s on %s: %v", name, wsPort, err)
			} else {
				log.Printf("WebSocket server started for %s on %s", name, wsPort)
				readyCh <- struct{}{}
			}
		}(node.name, node.wsPort)

		// Start P2P server
		p2pServers[i] = p2p.NewServer(node.addr, ip, port, seedList, blockchain)
		wg.Add(1)
		go func(name string, server *p2p.Server) {
			defer wg.Done()
			log.Printf("Starting P2P server for %s on %s", name, server.LocalNode().Address)
			if err := server.Start(); err != nil {
				log.Printf("P2P server failed for %s: %v", name, err)
			} else {
				log.Printf("P2P server started for %s on %s", name, server.LocalNode().Address)
				readyCh <- struct{}{}
			}
		}(node.name, p2pServers[i])

		// Set node role and verify key generation
		localNode := p2pServers[i].LocalNode()
		localNode.UpdateRole(node.role)
		log.Printf("Node %s initialized with role %s at %s", node.name, node.role, node.addr)

		// Test key generation
		if len(localNode.PublicKey) == 0 || len(localNode.PrivateKey) == 0 {
			log.Fatalf("Key generation failed for %s: empty public or private key", node.name)
		}
		publicKeyHex := hex.EncodeToString(localNode.PublicKey)
		log.Printf("Node %s public key: %s", node.name, publicKeyHex)

		// Check for unique public keys
		if _, exists := publicKeys[publicKeyHex]; exists {
			log.Fatalf("Duplicate public key detected for %s: %s", node.name, publicKeyHex)
		}
		publicKeys[publicKeyHex] = node.name
	}

	// Wait for all servers to be ready (4 servers per node: TCP, HTTP, WebSocket, P2P)
	for i := 0; i < len(nodes)*4; i++ {
		<-readyCh
	}
	log.Println("All servers are ready")

	// Add delay to ensure servers are fully bound
	time.Sleep(5 * time.Second)

	// Simulate sending a transaction from Alice to Bob
	tx := &types.Transaction{
		Sender:    "127.0.0.1:30303",
		Receiver:  "127.0.0.1:30304",
		Amount:    big.NewInt(1000),
		GasLimit:  big.NewInt(21000),
		GasPrice:  big.NewInt(1),
		Timestamp: time.Now().Unix(),
		Nonce:     1,
	}

	log.Printf("Submitting transaction from Alice to Bob: %+v", tx)
	err = http.SubmitTransaction(*httpAddr, *tx)
	if err != nil {
		log.Printf("Failed to submit transaction: %v", err)
	} else {
		log.Printf("Transaction submitted successfully! Sender: %s, Receiver: %s, Amount: %s, Nonce: %d",
			tx.Sender, tx.Receiver, tx.Amount.String(), tx.Nonce)
	}

	// Periodically prune inactive peers
	go func() {
		for {
			for _, server := range p2pServers {
				server.NodeManager().PruneInactivePeers(30 * time.Second)
			}
			time.Sleep(10 * time.Second)
		}
	}()

	// Keep main running
	select {}
}
