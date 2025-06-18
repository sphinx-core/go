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

// go/src/network/port.go
package network

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// LoadFromFile reads a JSON configuration file and unmarshals it into a slice of NodePortConfig.
func LoadFromFile(file string) ([]NodePortConfig, error) {
	// Read the entire content of the given file
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	// Parse JSON into NodePortConfig slice
	var configs []NodePortConfig
	if err := json.Unmarshal(data, &configs); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}
	return configs, nil
}

// GetNodePortConfigs generates a list of node port configurations for the specified number of nodes.
// It supports role assignment and allows overriding port values using flags.
func GetNodePortConfigs(numNodes int, roles []NodeRole, flagOverrides map[string]string) ([]NodePortConfig, error) {
	// Validate number of nodes
	if numNodes < 1 {
		return nil, fmt.Errorf("number of nodes must be at least 1")
	}
	// Ensure that each node has a corresponding role
	if len(roles) != numNodes {
		return nil, fmt.Errorf("number of roles (%d) must match number of nodes (%d)", len(roles), numNodes)
	}

	// Define base ports for each service type with room between them to avoid overlap
	const (
		baseTCPPort  = 30303 // Starting TCP port
		baseHTTPPort = 8545  // Starting HTTP port
		baseWSPort   = 8600  // Starting WebSocket port
		portStep     = 3     // Step increment for each node to avoid collisions
	)

	// Precompute all TCP addresses either from flags or by using default values
	tcpAddrs := make([]string, numNodes)
	for i := 0; i < numNodes; i++ {
		tcpPort := baseTCPPort + (i * portStep)
		// Allow overriding TCP address via flags
		if addr, ok := flagOverrides[fmt.Sprintf("tcpAddr%d", i)]; ok {
			tcpAddrs[i] = addr
		} else {
			tcpAddrs[i] = fmt.Sprintf("127.0.0.1:%d", tcpPort)
		}
	}

	// Create the node configurations
	configs := make([]NodePortConfig, numNodes)
	for i := 0; i < numNodes; i++ {
		// Node name based on index (e.g., "Node-0")
		name := fmt.Sprintf("Node-%d", i)

		// Role for this node from input slice
		role := roles[i]

		// TCP address, either default or overridden
		tcpAddr := tcpAddrs[i]

		// Compute HTTP port for node or use override
		httpPort := fmt.Sprintf("127.0.0.1:%d", baseHTTPPort+(i*portStep))
		if port, ok := flagOverrides[fmt.Sprintf("httpPort%d", i)]; ok {
			httpPort = port
		}

		// Compute WebSocket port or use override
		wsPort := fmt.Sprintf("127.0.0.1:%d", baseWSPort+(i*portStep))
		if port, ok := flagOverrides[fmt.Sprintf("wsPort%d", i)]; ok {
			wsPort = port
		}

		// Seed nodes: all TCP addresses except the current node’s
		seedNodes := make([]string, 0, numNodes-1)
		if seeds, ok := flagOverrides["seeds"]; ok {
			// If custom seed list is provided via flags, use it
			seedNodes = strings.Split(seeds, ",")
		} else {
			// Otherwise, include all other nodes’ TCP addresses
			for j, addr := range tcpAddrs {
				if j != i {
					seedNodes = append(seedNodes, addr)
				}
			}
		}

		// Assign computed configuration to the result list
		configs[i] = NodePortConfig{
			Name:      name,
			Role:      role,
			TCPAddr:   tcpAddr,
			HTTPPort:  httpPort,
			WSPort:    wsPort,
			SeedNodes: seedNodes,
		}
	}

	// Check for duplicate ports across all nodes to ensure uniqueness
	portSet := make(map[string]struct{})
	for _, config := range configs {
		// Check TCP, HTTP, and WS ports
		for _, addr := range []string{config.TCPAddr, config.HTTPPort, config.WSPort} {
			if _, exists := portSet[addr]; exists {
				// Return error if duplicate found
				return nil, fmt.Errorf("duplicate port %s for node %s", addr, config.Name)
			}
			portSet[addr] = struct{}{}
		}
	}

	// Return the generated list of node configurations
	return configs, nil
}
