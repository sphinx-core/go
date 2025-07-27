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

// go/src/bind/nodes.go
package bind

import (
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/sphinx-core/go/src/core"
	security "github.com/sphinx-core/go/src/handshake"
	logger "github.com/sphinx-core/go/src/log"
	"github.com/sphinx-core/go/src/network"
	"github.com/sphinx-core/go/src/p2p"
	"github.com/sphinx-core/go/src/rpc"
	"github.com/sphinx-core/go/src/transport"
	"github.com/syndtr/goleveldb/leveldb"
)

// SetupNodes initializes and starts all servers for the given node configurations.
func SetupNodes(configs []NodeSetupConfig, wg *sync.WaitGroup) ([]NodeResources, error) {
	messageChans := make([]chan *security.Message, len(configs))
	blockchains := make([]*core.Blockchain, len(configs))
	rpcServers := make([]*rpc.Server, len(configs))
	p2pServers := make([]*p2p.Server, len(configs))
	publicKeys := make(map[string]string)
	readyCh := make(chan struct{}, len(configs)*3) // 3 services per node (HTTP, WS, P2P)
	tcpReadyCh := make(chan struct{}, len(configs))

	// Initialize resources and TCP server configs
	tcpConfigs := make([]NodeConfig, len(configs))
	for i, config := range configs {
		parts := strings.Split(config.Address, ":")
		if len(parts) != 2 {
			logger.Errorf("Invalid address format for %s: %s", config.Name, config.Address)
			return nil, fmt.Errorf("invalid address format for %s: %s", config.Name, config.Address)
		}
		ip, port := parts[0], parts[1]
		if err := transport.ValidateIP(ip, port); err != nil {
			logger.Errorf("Invalid IP or port for %s: %v", config.Name, err)
			return nil, fmt.Errorf("invalid IP or port for %s: %v", config.Name, err)
		}

		logger.Infof("Initializing blockchain for %s", config.Name)
		blockchains[i] = core.NewBlockchain()
		logger.Infof("Genesis block created for %s, hash: %x", config.Name, blockchains[i].GetBestBlockHash())

		messageChans[i] = make(chan *security.Message, 1000)
		rpcServers[i] = rpc.NewServer(messageChans[i], blockchains[i])

		tcpConfigs[i] = NodeConfig{
			Address:   config.Address,
			Name:      config.Name,
			MessageCh: messageChans[i],
			RPCServer: rpcServers[i],
			ReadyCh:   tcpReadyCh,
		}

		db, err := leveldb.OpenFile(fmt.Sprintf("data/%s.db", config.Name), nil)
		if err != nil {
			logger.Errorf("Failed to open LevelDB for %s: %v", config.Name, err)
			return nil, fmt.Errorf("failed to open LevelDB for %s: %w", config.Name, err)
		}

		// Initialize P2P server
		p2pServers[i] = p2p.NewServer(network.NodePortConfig{
			Name:      config.Name,
			Role:      config.Role,
			TCPAddr:   config.Address,
			UDPPort:   config.Address, // Adjust if needed
			HTTPPort:  config.HTTPPort,
			WSPort:    config.WSPort,
			SeedNodes: config.SeedNodes,
		}, blockchains[i], db)
		localNode := p2pServers[i].LocalNode()
		localNode.UpdateRole(config.Role)
		logger.Infof("Node %s initialized with role %s", config.Name, config.Role)

		if len(localNode.PublicKey) == 0 || len(localNode.PrivateKey) == 0 {
			logger.Errorf("Key generation failed for %s", config.Name)
			return nil, fmt.Errorf("key generation failed for %s", config.Name)
		}

		pubHex := hex.EncodeToString(localNode.PublicKey)
		logger.Infof("Node %s public key: %s", config.Name, pubHex)
		if _, exists := publicKeys[pubHex]; exists {
			logger.Errorf("Duplicate public key detected for %s: %s", config.Name, pubHex)
			return nil, fmt.Errorf("duplicate public key detected for %s: %s", config.Name, pubHex)
		}
		publicKeys[pubHex] = config.Name
	}

	// Bind TCP servers
	if err := BindTCPServers(tcpConfigs, wg); err != nil {
		logger.Errorf("Failed to bind TCP servers: %v", err)
		return nil, err
	}

	// Wait for TCP servers to be ready
	logger.Infof("Waiting for %d TCP servers to be ready", len(configs))
	for i := 0; i < len(configs); i++ {
		select {
		case <-tcpReadyCh:
			logger.Infof("TCP server %d of %d ready", i+1, len(configs))
		case <-time.After(10 * time.Second):
			logger.Errorf("Timeout waiting for TCP server %d to be ready after 10s", i+1)
			return nil, fmt.Errorf("timeout waiting for TCP server %d to be ready after 10s", i+1)
		}
	}
	close(tcpReadyCh)
	logger.Infof("All TCP servers are ready")

	// Start HTTP, WebSocket, and P2P servers
	for i, config := range configs {
		// Start HTTP server
		startHTTPServer(config.Name, config.HTTPPort, messageChans[i], blockchains[i], readyCh, wg)

		// Start WebSocket server
		startWebSocketServer(config.Name, config.WSPort, messageChans[i], rpcServers[i], readyCh, wg)

		// Start P2P server
		startP2PServer(config.Name, p2pServers[i], readyCh, wg)
	}

	// Wait for all servers (HTTP, WS, P2P) to be ready
	logger.Infof("Waiting for %d servers to be ready", len(configs)*3)
	for i := 0; i < len(configs)*3; i++ {
		select {
		case <-readyCh:
			logger.Infof("Server %d of %d ready", i+1, len(configs)*3)
		case <-time.After(10 * time.Second):
			logger.Errorf("Timeout waiting for server %d to be ready after 10s", i+1)
			return nil, fmt.Errorf("timeout waiting for server %d to be ready after 10s", i+1)
		}
	}
	logger.Infof("All servers are ready")

	// Return node resources
	resources := make([]NodeResources, len(configs))
	for i := range configs {
		resources[i] = NodeResources{
			Blockchain: blockchains[i],
			MessageCh:  messageChans[i],
			RPCServer:  rpcServers[i],
			P2PServer:  p2pServers[i],
			PublicKey:  hex.EncodeToString(p2pServers[i].LocalNode().PublicKey),
		}
	}

	return resources, nil
}
