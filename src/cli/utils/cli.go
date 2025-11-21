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

// go/src/cli/utils/cli.go
package utils

import (
	"flag"
	"fmt"

	"github.com/sphinx-core/go/src/bind"
	"github.com/sphinx-core/go/src/network"
)

// ---------------------------------------------------------------------
// CLI entry point
// ---------------------------------------------------------------------
func Execute() error {
	cfg := &Config{}
	testCfg := &TestConfig{}

	// ----- standard CLI flags ------------------------------------------------
	flag.StringVar(&cfg.configFile, "config", "", "Path to node configuration JSON file")
	flag.IntVar(&cfg.numNodes, "nodes", 1, "Number of nodes to initialise")
	flag.StringVar(&cfg.roles, "roles", "none", "Comma-separated node roles (sender,receiver,validator,none)")
	flag.StringVar(&cfg.tcpAddr, "tcp-addr", "", "TCP address (e.g., 127.0.0.1:30303)")
	flag.StringVar(&cfg.udpPort, "udp-port", "", "UDP port for discovery (e.g., 30304)")
	flag.StringVar(&cfg.httpPort, "http-port", "", "HTTP port for API (e.g., 127.0.0.1:8545)")
	flag.StringVar(&cfg.wsPort, "ws-port", "", "WebSocket port (e.g., 127.0.0.1:8600)")
	flag.StringVar(&cfg.seedNodes, "seeds", "", "Comma-separated seed node UDP addresses")
	flag.StringVar(&cfg.dataDir, "datadir", "data", "Directory for LevelDB storage")
	flag.IntVar(&cfg.nodeIndex, "node-index", 0, "Index of the node to run (0 to numNodes-1)")

	// ----- test-only flag ----------------------------------------------------
	flag.IntVar(&testCfg.NumNodes, "test-nodes", 0,
		"Run the PBFT integration test with N validator nodes (0 = disabled)")

	flag.Parse()

	// ------------------------------------------------------------------------
	// 1. Test mode – no other flags allowed
	// ------------------------------------------------------------------------
	if testCfg.NumNodes > 0 {
		if flag.NFlag() > 1 {
			return fmt.Errorf("-test-nodes cannot be combined with other flags")
		}
		return CallConsensus(testCfg.NumNodes)
	}

	// ------------------------------------------------------------------------
	// 2. Normal mode (unchanged)
	// ------------------------------------------------------------------------
	if flag.NFlag() == 0 {
		// Use the bind package's RunTwoNodes function
		return bind.RunMultipleNodesInternal()
	}

	// ------------------------------------------------------------------------
	// 3. Config file or generated config
	// ------------------------------------------------------------------------
	var nodeConfig network.NodePortConfig
	if cfg.configFile != "" {
		// … unchanged (load from JSON) …
		configs, err := network.LoadFromFile(cfg.configFile)
		if err != nil {
			return fmt.Errorf("failed to load config file: %v", err)
		}
		if cfg.nodeIndex < 0 || cfg.nodeIndex >= len(configs) {
			return fmt.Errorf("node-index %d out of range for %d configs", cfg.nodeIndex, len(configs))
		}
		nodeConfig = configs[cfg.nodeIndex]
	} else {
		// Use the bind package's ParseRoles function
		roles := bind.ParseRoles(cfg.roles, cfg.numNodes)
		// … unchanged flag-overrides …
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

	// Use the bind package's StartSingleNode function
	return bind.StartSingleNodeInternal(nodeConfig, cfg.dataDir)
}
