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

const (
	baseTCPPort  = 31307 // Matches Node-0 TCPAddr
	baseUDPPort  = 31308 // Matches Node-0 UDPPort
	baseHTTPPort = 8545
	baseWSPort   = 8600
	portStep     = 2
)

// GetNodePortConfigs generates a list of node port configurations for the specified number of nodes.
func GetNodePortConfigs(numNodes int, roles []NodeRole, overrides map[string]string) ([]NodePortConfig, error) {
	configs := make([]NodePortConfig, numNodes)
	for i := 0; i < numNodes; i++ {
		name := fmt.Sprintf("Node-%d", i)
		tcpPort := baseTCPPort + i*portStep
		udpPort := baseUDPPort + i*portStep
		httpPort := baseHTTPPort + i
		wsPort := baseWSPort + i
		role := RoleNone
		if i < len(roles) {
			role = roles[i]
		}

		// Apply overrides
		tcpAddrKey := fmt.Sprintf("tcpAddr%d", i)
		udpPortKey := fmt.Sprintf("udpPort%d", i)
		httpPortKey := fmt.Sprintf("httpPort%d", i)
		wsPortKey := fmt.Sprintf("wsPort%d", i)

		tcpAddr := fmt.Sprintf("127.0.0.1:%d", tcpPort)
		if override, ok := overrides[tcpAddrKey]; ok {
			tcpAddr = override
		}
		udpAddr := fmt.Sprintf("127.0.0.1:%d", udpPort)
		if override, ok := overrides[udpPortKey]; ok {
			udpAddr = override
		}
		httpAddr := fmt.Sprintf("127.0.0.1:%d", httpPort)
		if override, ok := overrides[httpPortKey]; ok {
			httpAddr = override
		}
		wsAddr := fmt.Sprintf("127.0.0.1:%d", wsPort)
		if override, ok := overrides[wsPortKey]; ok {
			wsAddr = override
		}

		seedNodes := []string{}
		if seeds, ok := overrides["seeds"]; ok {
			seedNodes = strings.Split(seeds, ",")
		} else {
			for j := 0; j < numNodes; j++ {
				if j != i {
					seedNodes = append(seedNodes, fmt.Sprintf("127.0.0.1:%d", baseUDPPort+j*portStep))
				}
			}
		}

		configs[i] = NodePortConfig{
			Name:      name,
			TCPAddr:   tcpAddr,
			UDPPort:   udpAddr,
			HTTPPort:  httpAddr,
			WSPort:    wsAddr,
			Role:      role,
			SeedNodes: seedNodes,
		}
	}
	return configs, nil
}
