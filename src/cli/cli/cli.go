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
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sphinx-core/go/src/bind"
	config "github.com/sphinx-core/go/src/core/sphincs/config"
	key "github.com/sphinx-core/go/src/core/sphincs/key/backend"
	sign "github.com/sphinx-core/go/src/core/sphincs/sign/backend"
	"github.com/sphinx-core/go/src/network"
	"github.com/syndtr/goleveldb/leveldb"
)

// Execute runs the CLI to start network nodes with all backend servers.
func Execute() error {
	cfg := &Config{}
	flag.StringVar(&cfg.configFile, "config", "", "Path to node configuration JSON file")
	flag.IntVar(&cfg.numNodes, "nodes", 1, "Number of nodes to initialize")
	flag.StringVar(&cfg.roles, "roles", "none", "Comma-separated node roles (sender,receiver,validator,none)")
	flag.StringVar(&cfg.tcpAddr, "tcp-addr", "", "TCP address (e.g., 127.0.0.1:30303)")
	flag.StringVar(&cfg.udpPort, "udp-port", "", "UDP port for discovery (e.g., 30304)")
	flag.StringVar(&cfg.httpPort, "http-port", "", "HTTP port for API (e.g., 127.0.0.1:8545)")
	flag.StringVar(&cfg.wsPort, "ws-port", "", "WebSocket port (e.g., 127.0.0.1:8600)")
	flag.StringVar(&cfg.seedNodes, "seeds", "", "Comma-separated seed node UDP addresses")
	flag.StringVar(&cfg.dataDir, "datadir", "data", "Directory for LevelDB storage")
	flag.IntVar(&cfg.nodeIndex, "node-index", 0, "Index of the node to run (0 to numNodes-1)")
	flag.Parse()

	if flag.NFlag() == 0 {
		return runTwoNodes()
	}

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

// runTwoNodes starts three nodes with default configurations using the bind package.
func runTwoNodes() error {
	// Initialize wait group
	var wg sync.WaitGroup

	// Initialize used ports map to avoid conflicts
	usedPorts := make(map[int]bool)

	// Define base ports
	const baseTCPPort = 32307
	const baseUDPPort = 32418
	const baseHTTPPort = 8645
	const baseWSPort = 8700

	configs := make([]network.NodePortConfig, 3)
	dbs := make([]*leveldb.DB, 3)
	sphincsMgrs := make([]*sign.SphincsManager, 3)

	// Initialize LevelDB and SphincsManager for each node
	for i := 0; i < 3; i++ {
		dataDir := filepath.Join("data", fmt.Sprintf("Node-%d", i))
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			return fmt.Errorf("failed to create data directory %s: %v", dataDir, err)
		}

		db, err := leveldb.OpenFile(filepath.Join(dataDir, "leveldb"), nil)
		if err != nil {
			return fmt.Errorf("failed to open LevelDB at %s: %v", dataDir, err)
		}
		dbs[i] = db

		keyManager, err := key.NewKeyManager()
		if err != nil {
			return fmt.Errorf("failed to initialize KeyManager for Node-%d: %v", i, err)
		}

		sphincsParams, err := config.NewSPHINCSParameters()
		if err != nil {
			return fmt.Errorf("failed to initialize SPHINCSParameters for Node-%d: %v", i, err)
		}

		sphincsMgr := sign.NewSphincsManager(db, keyManager, sphincsParams)
		if sphincsMgr == nil {
			return fmt.Errorf("failed to initialize SphincsManager for Node-%d", i)
		}
		sphincsMgrs[i] = sphincsMgr

		// Find free TCP port
		tcpPort, err := network.FindFreePort(baseTCPPort+i*2, "tcp")
		if err != nil {
			return fmt.Errorf("failed to find free TCP port for Node-%d: %v", i, err)
		}
		usedPorts[tcpPort] = true
		tcpAddr := fmt.Sprintf("127.0.0.1:%d", tcpPort)

		// Find free UDP port
		udpPort, err := network.FindFreePort(baseUDPPort+i*2, "udp")
		if err != nil {
			return fmt.Errorf("failed to find free UDP port for Node-%d: %v", i, err)
		}
		usedPorts[udpPort] = true
		udpPortStr := fmt.Sprintf("%d", udpPort)

		// Find free HTTP port
		httpPort, err := network.FindFreePort(baseHTTPPort+i, "tcp")
		if err != nil {
			return fmt.Errorf("failed to find free HTTP port for Node-%d: %v", i, err)
		}
		usedPorts[httpPort] = true
		httpAddr := fmt.Sprintf("127.0.0.1:%d", httpPort)

		// Find free WebSocket port
		wsPort, err := network.FindFreePort(baseWSPort+i, "tcp")
		if err != nil {
			return fmt.Errorf("failed to find free WebSocket port for Node-%d: %v", i, err)
		}
		usedPorts[wsPort] = true
		wsAddr := fmt.Sprintf("127.0.0.1:%d", wsPort)

		configs[i] = network.NodePortConfig{
			ID:        fmt.Sprintf("Node-%d", i),
			Name:      fmt.Sprintf("Node-%d", i),
			TCPAddr:   tcpAddr,
			UDPPort:   udpPortStr,
			HTTPPort:  httpAddr,
			WSPort:    wsAddr,
			Role:      network.RoleNone,
			SeedNodes: []string{}, // Initialize empty; seeds will be set later
		}
		// Store initial config
		network.UpdateNodeConfig(configs[i])
	}

	// Convert []network.NodePortConfig to []bind.NodeSetupConfig
	setupConfigs := make([]bind.NodeSetupConfig, len(configs))
	for i, config := range configs {
		setupConfigs[i] = bind.NodeSetupConfig{
			Name:      config.Name,
			Address:   config.TCPAddr,
			UDPPort:   config.UDPPort,
			HTTPPort:  config.HTTPPort,
			WSPort:    config.WSPort,
			Role:      config.Role,
			SeedNodes: config.SeedNodes,
		}
	}

	resources, err := bind.SetupNodes(setupConfigs, &wg)
	if err != nil {
		return fmt.Errorf("failed to set up nodes: %v", err)
	}

	// Wait briefly to ensure P2P servers are initialized
	time.Sleep(2 * time.Second)
	for i := 0; i < 3; i++ {
		log.Printf("Checking P2P server for Node-%d: TCP=%s, UDP=%s", i, resources[i].P2PServer.LocalNode().Address, resources[i].P2PServer.LocalNode().UDPPort)
	}

	// Set SphincsManager for each P2PServer
	for i := 0; i < 3; i++ {
		resources[i].P2PServer.SetSphincsMgr(sphincsMgrs[i])
	}

	// Update seed nodes with actual UDP ports BEFORE calling DiscoverPeers
	for i, config := range configs {
		actualUDPPort := resources[i].P2PServer.LocalNode().UDPPort
		config.UDPPort = actualUDPPort
		seedNodes := []string{}
		for j := 0; j < 3; j++ {
			if j != i {
				seedConfig, exists := network.GetNodeConfig(fmt.Sprintf("Node-%d", j))
				if exists && seedConfig.UDPPort != "" {
					seedAddr := fmt.Sprintf("127.0.0.1:%s", seedConfig.UDPPort)
					// Validate seed node address
					if _, err := net.ResolveUDPAddr("udp", seedAddr); err != nil {
						log.Printf("Invalid seed node address for Node-%d: %s, error: %v", j, seedAddr, err)
						continue
					}
					seedNodes = append(seedNodes, seedAddr)
				}
			}
		}
		if len(seedNodes) == 0 {
			log.Printf("Warning: No valid seed nodes for Node-%d", i)
		}
		config.SeedNodes = seedNodes
		network.UpdateNodeConfig(config)
		resources[i].P2PServer.UpdateSeedNodes(config.SeedNodes)
		log.Printf("Updated seed nodes for Node-%d: %v", i, seedNodes)
	}

	// NOW call DiscoverPeers for each node
	for i := 0; i < 3; i++ {
		go func(idx int) {
			log.Printf("Starting DiscoverPeers for Node-%d", idx)
			if err := resources[idx].P2PServer.DiscoverPeers(); err != nil {
				log.Printf("DiscoverPeers failed for Node-%d: %v", idx, err)
			} else {
				log.Printf("DiscoverPeers completed successfully for Node-%d", idx)
			}
		}(i)
	}

	// Clear global configs and close databases on shutdown
	defer func() {
		network.ClearNodeConfigs()
		for i, db := range dbs {
			if err := db.Close(); err != nil {
				log.Printf("Failed to close LevelDB for Node-%d: %v", i, err)
			}
		}
	}()

	// Handle shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Println("Shutting down servers...")
	if err := bind.Shutdown(resources); err != nil {
		log.Printf("Failed to shut down servers: %v", err)
	}
	wg.Wait()
	return nil
}

// startNode starts a single node with the given configuration using the bind package.
func startNode(nodeConfig network.NodePortConfig, dataDir string) error {
	dataDir = filepath.Join(dataDir, nodeConfig.Name)
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return fmt.Errorf("failed to create data directory %s: %v", dataDir, err)
	}

	db, err := leveldb.OpenFile(filepath.Join(dataDir, "leveldb"), nil)
	if err != nil {
		return fmt.Errorf("failed to open LevelDB at %s: %v", dataDir, err)
	}
	defer db.Close()

	keyManager, err := key.NewKeyManager()
	if err != nil {
		return fmt.Errorf("failed to initialize KeyManager: %v", err)
	}

	sphincsParams, err := config.NewSPHINCSParameters()
	if err != nil {
		return fmt.Errorf("failed to initialize SPHINCSParameters: %v", err)
	}

	sphincsMgr := sign.NewSphincsManager(db, keyManager, sphincsParams)
	if sphincsMgr == nil {
		return fmt.Errorf("failed to initialize SphincsManager")
	}

	setupConfig := bind.NodeSetupConfig{
		Name:      nodeConfig.Name,
		Address:   nodeConfig.TCPAddr,
		UDPPort:   nodeConfig.UDPPort,
		HTTPPort:  nodeConfig.HTTPPort,
		WSPort:    nodeConfig.WSPort,
		Role:      nodeConfig.Role,
		SeedNodes: nodeConfig.SeedNodes,
	}

	var wg sync.WaitGroup
	resources, err := bind.SetupNodes([]bind.NodeSetupConfig{setupConfig}, &wg)
	if err != nil {
		return fmt.Errorf("failed to set up node %s: %v", nodeConfig.Name, err)
	}
	if len(resources) != 1 {
		return fmt.Errorf("expected 1 node resource, got %d", len(resources))
	}

	resources[0].P2PServer.SetSphincsMgr(sphincsMgr)

	// Start peer discovery after setup
	go func() {
		if err := resources[0].P2PServer.DiscoverPeers(); err != nil {
			log.Printf("DiscoverPeers failed for %s: %v", nodeConfig.Name, err)
		}
	}()

	log.Printf("Node %s started with role %s on TCP %s, UDP %s, HTTP %s, WebSocket %s",
		nodeConfig.Name, nodeConfig.Role, nodeConfig.TCPAddr, nodeConfig.UDPPort, nodeConfig.HTTPPort, nodeConfig.WSPort)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Printf("Shutting down node %s...", nodeConfig.Name)
	if err := bind.Shutdown([]bind.NodeResources{resources[0]}); err != nil {
		log.Printf("Failed to shut down node %s: %v", nodeConfig.Name, err)
	}
	wg.Wait()
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
