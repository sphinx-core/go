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

// go/src/network/config.go
package network

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func loadFromFile(file string) ([]NodePortConfig, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}
	var configs []NodePortConfig
	if err := json.Unmarshal(data, &configs); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}
	return configs, nil
}

// GetNodePortConfigs returns port configurations for nodes based on input parameters.
func GetNodePortConfigs(numNodes int, roles []NodeRole, flagOverrides map[string]string) ([]NodePortConfig, error) {
	// Validate inputs
	if numNodes < 1 {
		return nil, fmt.Errorf("number of nodes must be at least 1")
	}
	if len(roles) != numNodes {
		return nil, fmt.Errorf("number of roles (%d) must match number of nodes (%d)", len(roles), numNodes)
	}

	// Base ports with enough spacing (each node uses 3 ports: TCP, HTTP, WS)
	const (
		baseTCPPort  = 30303 // TCP: 30303, 30306, 30309, ...
		baseHTTPPort = 8545  // HTTP: 8545, 8548, 8551, ...
		baseWSPort   = 8600  // WS: 8600, 8603, 8606, ...
		portStep     = 3     // Increment by 3 to avoid overlap
	)

	// Collect all TCP addresses for seed node computation
	tcpAddrs := make([]string, numNodes)
	for i := 0; i < numNodes; i++ {
		tcpPort := baseTCPPort + (i * portStep)
		if addr, ok := flagOverrides[fmt.Sprintf("tcpAddr%d", i)]; ok {
			tcpAddrs[i] = addr
		} else {
			tcpAddrs[i] = fmt.Sprintf("127.0.0.1:%d", tcpPort)
		}
	}

	// Generate configurations
	configs := make([]NodePortConfig, numNodes)
	for i := 0; i < numNodes; i++ {
		// Name: Node-0, Node-1, etc.
		name := fmt.Sprintf("Node-%d", i)

		// Role: From provided roles slice
		role := roles[i]

		// TCP address: Already computed or overridden
		tcpAddr := tcpAddrs[i]

		// HTTP port: Base + offset or override
		httpPort := fmt.Sprintf("127.0.0.1:%d", baseHTTPPort+(i*portStep))
		if port, ok := flagOverrides[fmt.Sprintf("httpPort%d", i)]; ok {
			httpPort = port
		}

		// WebSocket port: Base + offset or override
		wsPort := fmt.Sprintf("127.0.0.1:%d", baseWSPort+(i*portStep))
		if port, ok := flagOverrides[fmt.Sprintf("wsPort%d", i)]; ok {
			wsPort = port
		}

		// Seed nodes: All TCP addresses except the node's own
		seedNodes := make([]string, 0, numNodes-1)
		if seeds, ok := flagOverrides["seeds"]; ok {
			seedNodes = strings.Split(seeds, ",")
		} else {
			for j, addr := range tcpAddrs {
				if j != i {
					seedNodes = append(seedNodes, addr)
				}
			}
		}

		configs[i] = NodePortConfig{
			Name:      name,
			Role:      role,
			TCPAddr:   tcpAddr,
			HTTPPort:  httpPort,
			WSPort:    wsPort,
			SeedNodes: seedNodes,
		}
	}

	// Check for port conflicts
	portSet := make(map[string]struct{})
	for _, config := range configs {
		for _, addr := range []string{config.TCPAddr, config.HTTPPort, config.WSPort} {
			if _, exists := portSet[addr]; exists {
				return nil, fmt.Errorf("duplicate port %s for node %s", addr, config.Name)
			}
			portSet[addr] = struct{}{}
		}
	}

	return configs, nil
}
