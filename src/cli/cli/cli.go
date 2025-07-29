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

// runTwoNodes starts two nodes with default configurations using the bind package.
func runTwoNodes() error {
	configs := []network.NodePortConfig{
		// Node-0
		{
			Name:      "Node-0",
			TCPAddr:   "127.0.0.1:30307",
			UDPPort:   "127.0.0.1:30308",
			HTTPPort:  "127.0.0.1:8547",
			WSPort:    "127.0.0.1:8602",
			Role:      network.RoleNone,
			SeedNodes: []string{"127.0.0.1:30310", "127.0.0.1:30312"},
		},
		// Node-1
		{
			Name:      "Node-1",
			TCPAddr:   "127.0.0.1:30309",
			UDPPort:   "127.0.0.1:30310",
			HTTPPort:  "127.0.0.1:8548",
			WSPort:    "127.0.0.1:8603",
			Role:      network.RoleNone,
			SeedNodes: []string{"127.0.0.1:30308", "127.0.0.1:30312"},
		},
		// Node-2
		{
			Name:      "Node-2",
			TCPAddr:   "127.0.0.1:30311",
			UDPPort:   "127.0.0.1:30312",
			HTTPPort:  "127.0.0.1:8549",
			WSPort:    "127.0.0.1:8604",
			Role:      network.RoleNone,
			SeedNodes: []string{"127.0.0.1:30308", "127.0.0.1:30310"},
		},
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

	var wg sync.WaitGroup
	resources, err := bind.SetupNodes(setupConfigs, &wg)
	if err != nil {
		return fmt.Errorf("failed to set up nodes: %v", err)
	}

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
	defer db.Close()

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

	// Convert network.NodePortConfig to bind.NodeSetupConfig
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

	// Set SphincsManager on P2P server
	resources[0].P2PServer.SetSphincsMgr(sphincsMgr)

	log.Printf("Node %s started with role %s on TCP %s, UDP %s, HTTP %s, WebSocket %s",
		nodeConfig.Name, nodeConfig.Role, nodeConfig.TCPAddr, nodeConfig.UDPPort, nodeConfig.HTTPPort, nodeConfig.WSPort)

	// Handle shutdown
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
