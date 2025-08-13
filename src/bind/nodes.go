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
	"github.com/sphinx-core/go/src/http"
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
	tcpServers := make([]*transport.TCPServer, len(configs))
	wsServers := make([]*transport.WebSocketServer, len(configs))
	httpServers := make([]*http.Server, len(configs))
	publicKeys := make(map[string]string)
	readyCh := make(chan struct{}, len(configs)*3) // 3 services per node (HTTP, WS, P2P)
	tcpReadyCh := make(chan struct{}, len(configs))
	p2pErrorCh := make(chan error, len(configs))
	udpReadyCh := make(chan struct{}, len(configs))
	dbs := make([]*leveldb.DB, len(configs)) // Track DBs for cleanup
	closed := make([]bool, len(configs))     // Track closed servers

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
		dbs[i] = db

		// Initialize p2p.Server with NodePortConfig, ensuring Node.ID is set
		nodeConfig := network.NodePortConfig{
			ID:        config.Name, // Set ID to match Name
			Name:      config.Name,
			TCPAddr:   config.Address,
			UDPPort:   config.UDPPort,
			HTTPPort:  config.HTTPPort,
			WSPort:    config.WSPort,
			Role:      config.Role,
			SeedNodes: config.SeedNodes,
		}
		p2pServers[i] = p2p.NewServer(nodeConfig, blockchains[i], db)
		localNode := p2pServers[i].LocalNode()
		localNode.ID = config.Name // Explicitly set Node.ID
		localNode.UpdateRole(config.Role)
		logger.Infof("Node %s initialized with ID %s and role %s", config.Name, localNode.ID, config.Role)

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

		tcpServers[i] = transport.NewTCPServer(config.Address, messageChans[i], rpcServers[i], tcpReadyCh)
		wsServers[i] = transport.NewWebSocketServer(config.WSPort, messageChans[i], rpcServers[i])
		httpServers[i] = http.NewServer(config.HTTPPort, messageChans[i], blockchains[i], readyCh)
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

	// Start P2P servers and wait for UDP listeners to be ready
	p2pReadyCh := make(chan struct{}, len(configs))
	for i, config := range configs {
		startP2PServer(config.Name, p2pServers[i], p2pReadyCh, p2pErrorCh, udpReadyCh, wg)
	}

	// Wait for all P2P servers to be ready or fail
	logger.Infof("Waiting for %d P2P servers to be ready", len(configs))
	for i := 0; i < len(configs); i++ {
		select {
		case <-p2pReadyCh:
			logger.Infof("P2P server %d of %d ready", i+1, len(configs))
		case err := <-p2pErrorCh:
			logger.Errorf("P2P server %d failed: %v", i+1, err)
			// Cleanup resources before returning
			for i, db := range dbs {
				if db != nil {
					db.Close()
					dbs[i] = nil
				}
			}
			for i, srv := range tcpServers {
				if srv != nil {
					srv.Stop()
					tcpServers[i] = nil
				}
			}
			for i, srv := range p2pServers {
				if srv != nil && !closed[i] {
					srv.Close()
					closed[i] = true
					p2pServers[i] = nil
				}
			}
			return nil, fmt.Errorf("P2P server %d failed: %v", i+1, err)
		case <-time.After(10 * time.Second):
			logger.Errorf("Timeout waiting for P2P server %d to be ready", i+1)
			// Cleanup resources before returning
			for i, db := range dbs {
				if db != nil {
					db.Close()
					dbs[i] = nil
				}
			}
			for i, srv := range tcpServers {
				if srv != nil {
					srv.Stop()
					tcpServers[i] = nil
				}
			}
			for i, srv := range p2pServers {
				if srv != nil && !closed[i] {
					srv.Close()
					closed[i] = true
					p2pServers[i] = nil
				}
			}
			return nil, fmt.Errorf("timeout waiting for P2P server %d to be ready", i+1)
		}
	}
	close(p2pReadyCh)

	// Wait for UDP listeners to be ready
	logger.Infof("Waiting for %d UDP listeners to be ready", len(configs))
	for i := 0; i < len(configs); i++ {
		select {
		case <-udpReadyCh:
			logger.Infof("UDP listener %d of %d ready", i+1, len(configs))
		case <-time.After(5 * time.Second):
			logger.Errorf("Timeout waiting for UDP listener %d to be ready", i+1)
			// Cleanup resources before returning
			for i, db := range dbs {
				if db != nil {
					db.Close()
					dbs[i] = nil
				}
			}
			for i, srv := range tcpServers {
				if srv != nil {
					srv.Stop()
					tcpServers[i] = nil
				}
			}
			for i, srv := range p2pServers {
				if srv != nil && !closed[i] {
					srv.Close()
					closed[i] = true
					p2pServers[i] = nil
				}
			}
			return nil, fmt.Errorf("timeout waiting for UDP listener %d to be ready", i+1)
		}
	}
	close(udpReadyCh)

	// Start peer discovery for all P2P servers
	for i, config := range configs {
		go func(name string, server *p2p.Server) {
			if err := server.DiscoverPeers(); err != nil {
				logger.Errorf("Peer discovery failed for %s: %v", name, err)
			} else {
				logger.Infof("Peer discovery completed for %s", name)
			}
		}(config.Name, p2pServers[i])
	}

	// Start HTTP and WebSocket servers
	for i, config := range configs {
		startHTTPServer(config.Name, config.HTTPPort, messageChans[i], blockchains[i], readyCh, wg)
		startWebSocketServer(config.Name, config.WSPort, messageChans[i], rpcServers[i], readyCh, wg)
	}

	// Wait for HTTP and WebSocket servers to be ready
	logger.Infof("Waiting for %d servers to be ready", len(configs)*2) // HTTP and WS only
	for i := 0; i < len(configs)*2; i++ {
		select {
		case <-readyCh:
			logger.Infof("Server %d of %d ready", i+1, len(configs)*2)
		case <-time.After(10 * time.Second):
			logger.Errorf("Timeout waiting for server %d to be ready after 10s", i+1)
			// Cleanup resources before returning
			for i, db := range dbs {
				if db != nil {
					db.Close()
					dbs[i] = nil
				}
			}
			for i, srv := range tcpServers {
				if srv != nil {
					srv.Stop()
					tcpServers[i] = nil
				}
			}
			for i, srv := range p2pServers {
				if srv != nil && !closed[i] {
					srv.Close()
					closed[i] = true
					p2pServers[i] = nil
				}
			}
			return nil, fmt.Errorf("timeout waiting for server %d to be ready after 10s", i+1)
		}
	}
	logger.Infof("All servers are ready")

	resources := make([]NodeResources, len(configs))
	for i := range configs {
		resources[i] = NodeResources{
			Blockchain:      blockchains[i],
			MessageCh:       messageChans[i],
			RPCServer:       rpcServers[i],
			P2PServer:       p2pServers[i],
			PublicKey:       hex.EncodeToString(p2pServers[i].LocalNode().PublicKey),
			TCPServer:       tcpServers[i],
			WebSocketServer: wsServers[i],
			HTTPServer:      httpServers[i],
		}
	}

	return resources, nil
}
