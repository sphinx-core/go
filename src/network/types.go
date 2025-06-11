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

// go/src/network/types.go
package network

import (
	"time"
)

// NodeStatus represents the operational state of a node.
type NodeStatus string

const (
	NodeStatusActive   NodeStatus = "active"
	NodeStatusInactive NodeStatus = "inactive"
	NodeStatusUnknown  NodeStatus = "unknown"
)

// Node represents a participant in the blockchain network.
type Node struct {
	ID       string     // Unique identifier for the node
	Address  string     // Network address (e.g., "192.168.1.1:8080")
	IP       string     // IP address (e.g., "192.168.1.1")
	Port     string     // Port number (e.g., "8080")
	Status   NodeStatus // Current status of the node
	LastSeen time.Time  // Last time the node was seen
	IsLocal  bool       // True if this is the local node
}

// Peer represents a node that another node is directly connected to.
type Peer struct {
	Node             *Node     // Reference to the node
	ConnectionStatus string    // Connection state (e.g., "connected", "disconnected")
	ConnectedAt      time.Time // Time of connection establishment
	LastPing         time.Time // Last time a PING was sent
	LastPong         time.Time // Last time a PONG was received
}

// PeerInfo represents information about a peer shared during discovery.
type PeerInfo struct {
	NodeID          string     `json:"node_id"`          // Unique ID of the peer
	Address         string     `json:"address"`          // Network address
	IP              string     `json:"ip"`               // IP address
	Port            string     `json:"port"`             // Port number
	Status          NodeStatus `json:"status"`           // Peer’s status
	Timestamp       time.Time  `json:"timestamp"`        // Time the info was generated
	ProtocolVersion string     `json:"protocol_version"` // Protocol version (e.g., "1.0")
}
