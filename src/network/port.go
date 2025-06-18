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
	"strings"
)

// HasSeenMessage checks if a message ID has been seen.
func (nm *NodeManager) HasSeenMessage(msgID string) bool {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	return nm.seenMsgs[msgID]
}

// MarkMessageSeen marks a message ID as seen.
func (nm *NodeManager) MarkMessageSeen(msgID string) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	nm.seenMsgs[msgID] = true
}

// GetNodePortConfigs returns port configurations for all nodes, applying flag overrides.
func GetNodePortConfigs(flagOverrides map[string]string) []NodePortConfig {
	// Default configurations
	defaultConfigs := []NodePortConfig{
		{
			Name:      "Alice",
			Role:      RoleSender,
			TCPAddr:   "127.0.0.1:30303",
			HTTPPort:  "127.0.0.1:8545",
			WSPort:    "127.0.0.1:8546",
			SeedNodes: []string{"127.0.0.1:30304", "127.0.0.1:30305"},
		},
		{
			Name:      "Bob",
			Role:      RoleReceiver,
			TCPAddr:   "127.0.0.1:30304",
			HTTPPort:  "127.0.0.1:8547",
			WSPort:    "127.0.0.1:8548",
			SeedNodes: []string{"127.0.0.1:30303", "127.0.0.1:30305"},
		},
		{
			Name:      "Charlie",
			Role:      RoleValidator,
			TCPAddr:   "127.0.0.1:30305",
			HTTPPort:  "127.0.0.1:8549",
			WSPort:    "127.0.0.1:8550",
			SeedNodes: []string{"127.0.0.1:30303", "127.0.0.1:30304"},
		},
	}

	// Apply flag overrides
	for i, config := range defaultConfigs {
		if addr, ok := flagOverrides["addr"+config.Name]; ok {
			defaultConfigs[i].TCPAddr = addr
		}

		if config.Name == "Alice" {
			if httpAddr, ok := flagOverrides["httpAddr"]; ok {
				defaultConfigs[i].HTTPPort = httpAddr
			}
		}

		if seeds, ok := flagOverrides["seeds"]; ok {
			defaultConfigs[i].SeedNodes = strings.Split(seeds, ",")
		}
	}

	return defaultConfigs
}
