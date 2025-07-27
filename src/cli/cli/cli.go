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

// go/src/cli/cli/cli.go
package cli

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	config "github.com/sphinx-core/go/src/core/sphincs/config"
	key "github.com/sphinx-core/go/src/core/sphincs/key/backend"
	sign "github.com/sphinx-core/go/src/core/sphincs/sign/backend"
	logger "github.com/sphinx-core/go/src/log"
	"github.com/sphinx-core/go/src/network"
	"github.com/sphinx-core/go/src/server"
	"github.com/syndtr/goleveldb/leveldb"
)

// Execute runs the CLI to start network nodes with all backend servers.
func Execute() error {
	cfg := &Config{}
	flag.StringVar(&cfg.configFile, "config", "", "Path to node configuration JSON file")
	flag.IntVar(&cfg.numNodes, "nodes", 1, "Number of nodes to initialize")
	flag.StringVar(&cfg.roles, "roles", "none", "Comma-separated node roles (sender,receiver,validator,none)")
	flag.StringVar(&cfg.tcpAddr, "tcp-addr", "", "TCP address (e.g., 127.0.0.1:30303)")
	flag.StringVar(&cfg.udpPort, "udp-port", "", "UDP port for discovery (e.g., 127.0.0.1:30304)")
	flag.StringVar(&cfg.httpPort, "http-port", "", "HTTP port for API (e.g., 127.0.0.1:8545)")
	flag.StringVar(&cfg.wsPort, "ws-port", "", "WebSocket port (e.g., 127.0.0.1:8600)")
	flag.StringVar(&cfg.seedNodes, "seeds", "", "Comma-separated seed node UDP addresses")
	flag.StringVar(&cfg.dataDir, "datadir", "data", "Directory for LevelDB storage")
	flag.IntVar(&cfg.nodeIndex, "node-index", 0, "Index of the node to run (0 to numNodes-1)")
	flag.Parse()

	// If no flags provided (VS Code "play" button), run two nodes
	if flag.NFlag() == 0 {
		return runTwoNodes()
	}

	// Load or generate node configuration
	var nodeConfig network.NodePortConfig
	if cfg.configFile != "" {
		configs, err := network.LoadFromFile(cfg.configFile)
		if err != nil {
			return fmt.Errorf("failed to load config file: %v", err)
		}
		if cfg.nodeIndex < 0 || cfg.nodeIndex >= len(configs) {
			return fmt.Errorf("node-index %d out of range for %d configs", cfg.nodeIndex, len(configs))
		}
		nodeConfig = configs[cfg.nodeIndex]
	} else {
		roles := parseRoles(cfg.roles, cfg.numNodes)
		flagOverrides := make(map[string]string)
		if cfg.tcpAddr != "" {
			flagOverrides[fmt.Sprintf("tcpAddr%d", cfg.nodeIndex)] = cfg.tcpAddr
		}
		if cfg.udpPort != "" {
			flagOverrides[fmt.Sprintf("udpPort%d", cfg.nodeIndex)] = cfg.udpPort
		}
		if cfg.httpPort != "" {
			flagOverrides[fmt.Sprintf("httpPort%d", cfg.nodeIndex)] = cfg.httpPort
		}
		if cfg.wsPort != "" {
			flagOverrides[fmt.Sprintf("wsPort%d", cfg.nodeIndex)] = cfg.wsPort
		}
		if cfg.seedNodes != "" {
			flagOverrides["seeds"] = cfg.seedNodes
		}
		configs, err := network.GetNodePortConfigs(cfg.numNodes, roles, flagOverrides)
		if err != nil {
			return fmt.Errorf("failed to generate node configs: %v", err)
		}
		if cfg.nodeIndex < 0 || cfg.nodeIndex >= len(configs) {
			return fmt.Errorf("node-index %d out of range for %d nodes", cfg.nodeIndex, cfg.numNodes)
		}
		nodeConfig = configs[cfg.nodeIndex]
	}

	return startNode(nodeConfig, cfg.dataDir)
}

// runTwoNodes starts two nodes with default configurations.
func runTwoNodes() error {
	// Define configurations for two nodes
	configs := []network.NodePortConfig{
		{
			Name:      "Node-0",
			TCPAddr:   "127.0.0.1:30307",
			UDPPort:   "127.0.0.1:30308",
			HTTPPort:  "127.0.0.1:8547",
			WSPort:    "127.0.0.1:8602",
			Role:      network.RoleNone,
			SeedNodes: []string{},
		},
		{
			Name:      "Node-1",
			TCPAddr:   "127.0.0.1:30309",
			UDPPort:   "127.0.0.1:30310",
			HTTPPort:  "127.0.0.1:8548",
			WSPort:    "127.0.0.1:8603",
			Role:      network.RoleNone,
			SeedNodes: []string{"127.0.0.1:30308"}, // Node-1 uses Node-0 as seed
		},
	}

	var wg sync.WaitGroup
	startErrCh := make(chan error, 2)
	srvCh := make(chan *server.Server, 2)

	// Start both nodes
	for i, nodeConfig := range configs {
		wg.Add(1)
		go func(idx int, cfg network.NodePortConfig) {
			defer wg.Done()
			logger.Infof("Starting node %s", cfg.Name)
			if err := startNode(cfg, "data"); err != nil {
				logger.Errorf("Failed to start node %s: %v", cfg.Name, err)
				startErrCh <- fmt.Errorf("node %s failed: %v", cfg.Name, err)
				return
			}
			srvCh <- server.GetServer(cfg.Name) // Assume server package tracks servers by name
		}(i, nodeConfig)
	}

	// Wait for servers to start
	servers := make([]*server.Server, 0, 2)
	for i := 0; i < 2; i++ {
		select {
		case srv := <-srvCh:
			servers = append(servers, srv)
		case err := <-startErrCh:
			for _, srv := range servers {
				srv.Close()
			}
			return err
		case <-time.After(10 * time.Second):
			for _, srv := range servers {
				srv.Close()
			}
			return fmt.Errorf("timeout waiting for node %d to start", i)
		}
	}

	// Handle shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Println("Shutting down servers...")
	for _, srv := range servers {
		if err := srv.Close(); err != nil {
			log.Printf("Failed to close server %s: %v", srv.P2PServer().LocalNode().Address, err)
		}
	}
	wg.Wait()
	return nil
}

// startNode starts a single node with the given configuration.
func startNode(nodeConfig network.NodePortConfig, dataDir string) error {
	// Create data directory
	dataDir = filepath.Join(dataDir, nodeConfig.Name)
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return fmt.Errorf("failed to create data directory %s: %v", dataDir, err)
	}

	// Initialize LevelDB
	db, err := leveldb.OpenFile(filepath.Join(dataDir, "leveldb"), nil)
	if err != nil {
		return fmt.Errorf("failed to open LevelDB at %s: %v", dataDir, err)
	}

	// Initialize KeyManager
	keyManager, err := key.NewKeyManager()
	if err != nil {
		return fmt.Errorf("failed to initialize KeyManager: %v", err)
	}

	// Initialize SPHINCSParameters
	sphincsParams, err := config.NewSPHINCSParameters()
	if err != nil {
		return fmt.Errorf("failed to initialize SPHINCSParameters: %v", err)
	}

	// Initialize SphincsManager
	sphincsMgr := sign.NewSphincsManager(db, keyManager, sphincsParams)
	if sphincsMgr == nil {
		return fmt.Errorf("failed to initialize SphincsManager")
	}

	// Initialize full server (TCP, WebSocket, HTTP, P2P)
	readyCh := make(chan struct{}, 4) // Buffer for all 4 servers
	srv := server.NewServer(nodeConfig.TCPAddr, nodeConfig.WSPort, nodeConfig.HTTPPort, nodeConfig.UDPPort, nodeConfig.SeedNodes, db, readyCh, nodeConfig.Role)
	srv.P2PServer().SetSphincsMgr(sphincsMgr)

	// Start servers with wait group and readiness channel
	var wg sync.WaitGroup
	startErrCh := make(chan error, 4) // For TCP, HTTP, WebSocket, P2P servers

	// Start TCP server
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Infof("Starting TCP server for %s on %s", nodeConfig.Name, nodeConfig.TCPAddr)
		if err := srv.TCPServer().Start(); err != nil {
			logger.Errorf("TCP server failed for %s: %v", nodeConfig.Name, err)
			startErrCh <- fmt.Errorf("TCP server failed: %v", err)
			return
		}
		logger.Infof("TCP server for %s started successfully", nodeConfig.Name)
	}()

	// Start HTTP server
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Infof("Starting HTTP server for %s on %s", nodeConfig.Name, nodeConfig.HTTPPort)
		if err := srv.HTTPServer().Start(); err != nil {
			logger.Errorf("HTTP server failed for %s: %v", nodeConfig.Name, err)
			startErrCh <- fmt.Errorf("HTTP server failed: %v", err)
			return
		}
		logger.Infof("HTTP server for %s started successfully", nodeConfig.Name)
	}()

	// Start WebSocket server
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Infof("Starting WebSocket server for %s on %s", nodeConfig.Name, nodeConfig.WSPort)
		if err := srv.WSServer().Start(readyCh); err != nil {
			logger.Errorf("WebSocket server failed for %s: %v", nodeConfig.Name, err)
			startErrCh <- fmt.Errorf("WebSocket server failed: %v", err)
			return
		}
		logger.Infof("WebSocket server for %s started successfully", nodeConfig.Name)
	}()

	// Start P2P server
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Infof("Starting P2P server for %s on %s", nodeConfig.Name, srv.P2PServer().LocalNode().Address)
		startCh := make(chan error, 1)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Errorf("Panic in P2P server startup for %s: %v", nodeConfig.Name, r)
					startCh <- fmt.Errorf("panic: %v", r)
				}
			}()
			err := srv.P2PServer().Start()
			startCh <- err
		}()
		select {
		case err := <-startCh:
			if err != nil {
				logger.Errorf("P2P server failed for %s: %v", nodeConfig.Name, err)
				startErrCh <- fmt.Errorf("P2P server failed: %v", err)
				return
			}
			logger.Infof("P2P server for %s started successfully", nodeConfig.Name)
			readyCh <- struct{}{}
		case <-time.After(2 * time.Second):
			logger.Warnf("P2P server for %s took too long to start, assuming ready", nodeConfig.Name)
			readyCh <- struct{}{}
		}
	}()

	// Wait for all servers to be ready or fail
	for i := 0; i < 4; i++ {
		select {
		case <-readyCh:
			logger.Infof("Server component %d for %s is ready", i+1, nodeConfig.Name)
		case err := <-startErrCh:
			srv.Close()
			return fmt.Errorf("failed to start server component: %v", err)
		case <-time.After(10 * time.Second):
			srv.Close()
			return fmt.Errorf("timeout waiting for server component %d to start for %s", i+1, nodeConfig.Name)
		}
	}

	log.Printf("Node %s started with role %s on TCP %s, UDP %s, HTTP %s, WebSocket %s",
		nodeConfig.Name, nodeConfig.Role, nodeConfig.TCPAddr, nodeConfig.UDPPort, nodeConfig.HTTPPort, nodeConfig.WSPort)

	// Store server for shutdown (temporary hack for runTwoNodes)
	server.StoreServer(nodeConfig.Name, srv)

	return nil
}

// parseRoles converts a comma-separated roles string into a slice of NodeRole.
func parseRoles(rolesStr string, numNodes int) []network.NodeRole {
	roles := strings.Split(rolesStr, ",")
	result := make([]network.NodeRole, numNodes)
	for i := 0; i < numNodes; i++ {
		if i < len(roles) {
			switch strings.TrimSpace(roles[i]) {
			case "sender":
				result[i] = network.RoleSender
			case "receiver":
				result[i] = network.RoleReceiver
			case "validator":
				result[i] = network.RoleValidator
			default:
				result[i] = network.RoleNone
			}
		} else {
			result[i] = network.RoleNone
		}
	}
	return result
}
