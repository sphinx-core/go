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
	"encoding/hex"
	"flag"
	"math/big"
	"runtime"
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
	logger.Init()

	addrAlice := flag.String("addrAlice", "127.0.0.1:30303", "TCP server address for Alice")
	addrBob := flag.String("addrBob", "127.0.0.1:30304", "TCP server address for Bob")
	addrCharlie := flag.String("addrCharlie", "127.0.0.1:30305", "TCP server address for Charlie")
	httpAddr := flag.String("httpAddr", "127.0.0.1:8545", "HTTP server address for Alice")
	seeds := flag.String("seeds", "127.0.0.1:30304,127.0.0.1:30305", "Comma-separated list of seed nodes")
	flag.Parse()

	var wg sync.WaitGroup
	readyCh := make(chan struct{}, 3*4)  // 3 nodes × 4 services (TCP, HTTP, WS, P2P)
	tcpReadyCh := make(chan struct{}, 3) // Channel for TCP server readiness

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

	// Start all servers and collect TCP readiness signals
	for i, node := range nodes {
		parts := strings.Split(node.addr, ":")
		if len(parts) != 2 {
			logger.Fatalf("Invalid address format for %s: %s", node.name, node.addr)
		}
		ip, port := parts[0], parts[1]
		if err := transport.ValidateIP(ip, port); err != nil {
			logger.Fatalf("Invalid IP or port for %s: %v", node.name, err)
		}

		logger.Infof("Initializing blockchain for %s", node.name)
		blockchain := core.NewBlockchain()
		logger.Infof("Genesis block created for %s, hash: %x", node.name, blockchain.GetBestBlockHash())

		messageChans[i] = make(chan *security.Message, 100)
		rpcServer := rpc.NewServer(messageChans[i], blockchain)

		// Start TCP server
		tcpServer := transport.NewTCPServer(node.addr, messageChans[i], rpcServer)
		wg.Add(1)
		go func(name, addr string) {
			defer wg.Done()
			logger.Infof("Starting TCP server for %s on %s", name, addr)
			if err := tcpServer.Start(); err != nil {
				logger.Errorf("TCP server failed for %s: %v", name, err)
			} else {
				logger.Infof("TCP server for %s successfully started", name)
				readyCh <- struct{}{}
				logger.Infof("Preparing to send TCP ready signal for %s", name)
				tcpReadyCh <- struct{}{} // Signal TCP server is ready
				logger.Infof("Sent TCP ready signal for %s", name)
			}
		}(node.name, node.addr)

		// Start HTTP server
		httpServer := http.NewServer(node.httpPort, messageChans[i], blockchain)
		wg.Add(1)
		go func(name, port string) {
			defer wg.Done()
			logger.Infof("Starting HTTP server for %s on %s", name, port)
			if err := httpServer.Start(); err != nil {
				logger.Errorf("HTTP server failed for %s: %v", name, err)
			} else {
				logger.Infof("HTTP server for %s successfully started", name)
				readyCh <- struct{}{}
			}
		}(node.name, node.httpPort)

		// Start WebSocket server
		wsServer := transport.NewWebSocketServer(node.wsPort, messageChans[i], rpcServer)
		wg.Add(1)
		go func(name, port string) {
			defer wg.Done()
			logger.Infof("Starting WebSocket server for %s on %s", name, port)
			if err := wsServer.Start(); err != nil {
				logger.Errorf("WebSocket server failed for %s: %v", name, err)
			} else {
				logger.Infof("WebSocket server for %s successfully started", name)
				readyCh <- struct{}{}
			}
		}(node.name, node.wsPort)

		// Initialize P2P server but don't start it yet
		p2pServers[i] = p2p.NewServer(node.addr, ip, port, seedList, blockchain)

		localNode := p2pServers[i].LocalNode()
		localNode.UpdateRole(node.role)
		logger.Infof("Node %s initialized with role %s", node.name, node.role)

		if len(localNode.PublicKey) == 0 || len(localNode.PrivateKey) == 0 {
			logger.Fatalf("Key generation failed for %s", node.name)
		}

		pubHex := hex.EncodeToString(localNode.PublicKey)
		logger.Infof("Node %s public key: %s", node.name, pubHex)

		if _, exists := publicKeys[pubHex]; exists {
			logger.Fatalf("Duplicate public key detected for %s: %s", node.name, pubHex)
		}
		publicKeys[pubHex] = node.name
	}

	// Wait for all TCP servers to be ready
	logger.Infof("Waiting for %d TCP servers to be ready", len(nodes))
	for i := 0; i < len(nodes); i++ {
		select {
		case <-tcpReadyCh:
			logger.Infof("TCP server %d of %d ready", i+1, len(nodes))
		case <-time.After(5 * time.Second):
			logger.Errorf("Timeout waiting for TCP server %d to be ready after 5s", i+1)
			logger.Fatalf("Failed to receive all TCP ready signals")
		}
		runtime.Gosched() // Yield to allow other goroutines to run
	}
	close(tcpReadyCh) // Close the channel to prevent further sends
	logger.Infof("All TCP servers are ready")

	// Start P2P servers
	for i, node := range nodes {
		wg.Add(1)
		go func(name string, server *p2p.Server) {
			defer wg.Done()
			logger.Infof("Starting P2P server for %s on %s", name, server.LocalNode().Address)
			if err := server.Start(); err != nil {
				logger.Errorf("P2P server failed for %s: %v", name, err)
			} else {
				logger.Infof("P2P server for %s successfully started", name)
				readyCh <- struct{}{}
			}
		}(node.name, p2pServers[i])
	}

	// Wait until all servers are ready
	for i := 0; i < len(nodes)*4; i++ {
		select {
		case <-readyCh:
			logger.Infof("Server %d of %d ready", i+1, len(nodes)*4)
		case <-time.After(15 * time.Second):
			logger.Fatalf("Timeout waiting for server %d to be ready", i+1)
		}
	}
	logger.Infof("All servers are ready")

	// Simulate a delay before submitting a transaction
	time.Sleep(5 * time.Second)

	tx := &types.Transaction{
		Sender:    "127.0.0.1:30303",
		Receiver:  "127.0.0.1:30304",
		Amount:    big.NewInt(1000),
		GasLimit:  big.NewInt(21000),
		GasPrice:  big.NewInt(1),
		Timestamp: time.Now().Unix(),
		Nonce:     1,
	}

	logger.Infof("Submitting transaction from Alice to Bob: %+v", tx)
	err := http.SubmitTransaction(*httpAddr, *tx)
	if err != nil {
		logger.Errorf("Failed to submit transaction: %v", err)
	} else {
		logger.Infof("Transaction submitted successfully! Sender: %s, Receiver: %s, Amount: %s, Nonce: %d",
			tx.Sender, tx.Receiver, tx.Amount.String(), tx.Nonce)
	}

	go func() {
		for {
			for _, server := range p2pServers {
				server.NodeManager().PruneInactivePeers(30 * time.Second)
			}
			time.Sleep(10 * time.Second)
		}
	}()

	select {}
}
