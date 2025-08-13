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
	"log"
	"net"
	"os"
	"strings"
	"sync"
)

// Global configuration store
var (
	NodeConfigs     = make(map[string]NodePortConfig) // Map node ID to config
	NodeConfigsLock sync.RWMutex                      // Mutex for thread-safe access
)

// ClearNodeConfigs clears the global node configurations in a thread-safe manner.
func ClearNodeConfigs() {
	NodeConfigsLock.Lock()
	defer NodeConfigsLock.Unlock()
	NodeConfigs = make(map[string]NodePortConfig)
}

// UpdateNodeConfig updates the global configuration for a node.
func UpdateNodeConfig(config NodePortConfig) {
	NodeConfigsLock.Lock()
	defer NodeConfigsLock.Unlock()
	NodeConfigs[config.ID] = config
}

// GetNodeConfig retrieves the configuration for a node by ID.
func GetNodeConfig(id string) (NodePortConfig, bool) {
	NodeConfigsLock.RLock()
	defer NodeConfigsLock.RUnlock()
	config, exists := NodeConfigs[id]
	return config, exists
}

// LoadFromFile reads a JSON configuration file and unmarshals it into a slice of NodePortConfig.
func LoadFromFile(file string) ([]NodePortConfig, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}
	var configs []NodePortConfig
	if err := json.Unmarshal(data, &configs); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}
	// Store loaded configs in global store
	NodeConfigsLock.Lock()
	for _, config := range configs {
		NodeConfigs[config.ID] = config
	}
	NodeConfigsLock.Unlock()
	return configs, nil
}

const (
	baseTCPPort  = 32307
	baseUDPPort  = 32418
	baseHTTPPort = 8645
	baseWSPort   = 8700
	portStep     = 10 // Increased to reduce localhost conflicts
)

// FindFreePort finds an available port starting from basePort.
func FindFreePort(basePort int, protocol string) (int, error) {
	for port := basePort; port <= 65535; port++ {
		var ln interface{}
		var err error
		if protocol == "tcp" {
			tcpAddr := &net.TCPAddr{Port: port, IP: net.ParseIP("0.0.0.0")}
			ln, err = net.ListenTCP("tcp", tcpAddr)
		} else {
			udpAddr := &net.UDPAddr{Port: port, IP: net.ParseIP("0.0.0.0")}
			ln, err = net.ListenUDP("udp", udpAddr)
		}
		if err == nil {
			switch conn := ln.(type) {
			case *net.TCPListener:
				conn.Close()
			case *net.UDPConn:
				conn.Close()
			}
			return port, nil
		}
	}
	return 0, fmt.Errorf("no free %s ports available starting from %d", protocol, basePort)
}

// GetNodePortConfigs generates or retrieves a list of node port configurations.
func GetNodePortConfigs(numNodes int, roles []NodeRole, overrides map[string]string) ([]NodePortConfig, error) {
	NodeConfigsLock.RLock()
	if len(NodeConfigs) >= numNodes {
		configs := make([]NodePortConfig, 0, numNodes)
		for i := 0; i < numNodes; i++ {
			id := fmt.Sprintf("Node-%d", i)
			if config, exists := NodeConfigs[id]; exists {
				configs = append(configs, config)
			} else {
				NodeConfigsLock.RUnlock()
				return nil, fmt.Errorf("configuration for node %s not found", id)
			}
		}
		NodeConfigsLock.RUnlock()
		return configs, nil
	}
	NodeConfigsLock.RUnlock()

	// Generate new configurations if none exist
	configs := make([]NodePortConfig, numNodes)
	usedPorts := make(map[int]bool)

	for i := 0; i < numNodes; i++ {
		name := fmt.Sprintf("Node-%d", i)
		id := name // Use name as ID for consistency
		role := RoleNone
		if i < len(roles) {
			role = roles[i]
		}

		// Default ports
		tcpPort := baseTCPPort + i*portStep
		udpPort := baseUDPPort + i*portStep
		httpPort := baseHTTPPort + i
		wsPort := baseWSPort + i

		tcpAddrKey := fmt.Sprintf("tcpAddr%d", i)
		udpPortKey := fmt.Sprintf("udpPort%d", i)
		httpPortKey := fmt.Sprintf("httpPort%d", i)
		wsPortKey := fmt.Sprintf("wsPort%d", i)

		// TCP port
		var tcpAddr string
		if override, ok := overrides[tcpAddrKey]; ok {
			tcpAddr = override
		} else {
			for usedPorts[tcpPort] {
				var err error
				tcpPort, err = FindFreePort(tcpPort+portStep, "tcp")
				if err != nil {
					return nil, fmt.Errorf("failed to find free TCP port for node %s: %v", id, err)
				}
			}
			usedPorts[tcpPort] = true
			tcpAddr = fmt.Sprintf("127.0.0.1:%d", tcpPort)
		}

		// UDP port
		var udpPortStr string
		if override, ok := overrides[udpPortKey]; ok {
			udpPortStr = override
		} else {
			for usedPorts[udpPort] {
				var err error
				udpPort, err = FindFreePort(udpPort+portStep, "udp")
				if err != nil {
					return nil, fmt.Errorf("failed to find free UDP port for node %s: %v", id, err)
				}
			}
			usedPorts[udpPort] = true
			udpPortStr = fmt.Sprintf("%d", udpPort)
		}

		// HTTP port
		var httpAddr string
		if override, ok := overrides[httpPortKey]; ok {
			httpAddr = override
		} else {
			for usedPorts[httpPort] {
				var err error
				httpPort, err = FindFreePort(httpPort+1, "tcp")
				if err != nil {
					return nil, fmt.Errorf("failed to find free HTTP port for node %s: %v", id, err)
				}
			}
			usedPorts[httpPort] = true
			httpAddr = fmt.Sprintf("127.0.0.1:%d", httpPort)
		}

		// WebSocket port
		var wsAddr string
		if override, ok := overrides[wsPortKey]; ok {
			wsAddr = override
		} else {
			for usedPorts[wsPort] {
				var err error
				wsPort, err = FindFreePort(wsPort+1, "tcp")
				if err != nil {
					return nil, fmt.Errorf("failed to find free WebSocket port for node %s: %v", id, err)
				}
			}
			usedPorts[wsPort] = true
			wsAddr = fmt.Sprintf("127.0.0.1:%d", wsPort)
		}

		// Seeds (exclude self)
		seedNodes := []string{}
		if seeds, ok := overrides["seeds"]; ok {
			seedNodes = strings.Split(seeds, ",")
			// Validate seed nodes
			validSeeds := []string{}
			for _, seed := range seedNodes {
				seedPort := strings.Split(seed, ":")[len(strings.Split(seed, ":"))-1]
				expectedPorts := map[string]bool{
					"32418": true, "32419": true, "32420": true, "32421": true, // Adjust based on baseUDPPort
				}
				if expectedPorts[seedPort] {
					if _, err := net.ResolveUDPAddr("udp", seed); err == nil {
						validSeeds = append(validSeeds, seed)
					} else {
						log.Printf("GetNodePortConfigs: Invalid seed address %s for node %s: %v", seed, id, err)
					}
				} else {
					log.Printf("GetNodePortConfigs: Skipping unexpected seed port %s for node %s", seedPort, id)
				}
			}
			seedNodes = validSeeds
		} else {
			for j := 0; j < numNodes; j++ {
				if j != i { // Exclude self
					seedPort := baseUDPPort + j*portStep
					for usedPorts[seedPort] && seedPort != udpPort {
						var err error
						seedPort, err = FindFreePort(seedPort+portStep, "udp")
						if err != nil {
							return nil, fmt.Errorf("failed to find free seed UDP port for node %s: %v", id, err)
						}
					}
					seedNodes = append(seedNodes, fmt.Sprintf("127.0.0.1:%d", seedPort))
				}
			}
		}
		configs[i] = NodePortConfig{
			ID:        id,
			Name:      name,
			TCPAddr:   tcpAddr,
			UDPPort:   udpPortStr,
			HTTPPort:  httpAddr,
			WSPort:    wsAddr,
			Role:      role,
			SeedNodes: seedNodes,
		}
	}

	// Store generated configs
	NodeConfigsLock.Lock()
	for _, config := range configs {
		NodeConfigs[config.ID] = config
	}
	NodeConfigsLock.Unlock()

	return configs, nil
}
