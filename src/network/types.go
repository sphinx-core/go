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
	"sync"
	"time"
)

// NodeStatus represents the operational state of a node in the network.
type NodeStatus string

const (
	NodeStatusActive   NodeStatus = "active"
	NodeStatusInactive NodeStatus = "inactive"
	NodeStatusUnknown  NodeStatus = "unknown"
)

// NodeRole defines the role a node plays in a transaction or network operation.
type NodeRole string

const (
	RoleSender    NodeRole = "sender"    // Node sending a transaction (e.g., Alice)
	RoleReceiver  NodeRole = "receiver"  // Node receiving a transaction (e.g., Bob)
	RoleValidator NodeRole = "validator" // Node validating a transaction (e.g., Charlie)
	RoleNone      NodeRole = "none"      // Default role for nodes not involved in a specific transaction
)

// NodeManager manages nodes and their peers.
type NodeManager struct {
	nodes    map[string]*Node // All known nodes, keyed by Node.ID
	peers    map[string]*Peer // Connected peers, keyed by Node.ID
	seenMsgs map[string]bool  // Seen message IDs for deduplication
	mu       sync.RWMutex     // Thread safety for node and peer access
}

// Node represents a participant in the blockchain or P2P network.
type Node struct {
	ID         string     // Unique identifier (UUID)
	Address    string     // Network address (e.g., IP:port)
	IP         string     // IP address
	Port       string     // Port number
	Status     NodeStatus // Current status (active/inactive/unknown)
	Role       NodeRole   // Role in transactions (sender/receiver/validator/none)
	LastSeen   time.Time  // Last activity timestamp
	IsLocal    bool       // True if this is the local node
	PublicKey  []byte     // SPHINCS+ public key
	PrivateKey []byte     // SPHINCS+ private key
}

// Peer represents a directly connected node in the network.
type Peer struct {
	Node             *Node     // Associated node
	ConnectionStatus string    // connected/disconnected
	ConnectedAt      time.Time // Connection timestamp
	LastPing         time.Time // Last ping sent
	LastPong         time.Time // Last pong received
	LastSeen         time.Time // Last activity timestamp (added)
}

// PeerInfo is a shareable snapshot of peer metadata.
type PeerInfo struct {
	NodeID          string     `json:"node_id"`
	Address         string     `json:"address"`
	IP              string     `json:"ip"`
	Port            string     `json:"port"`
	Status          NodeStatus `json:"status"`
	Role            NodeRole   `json:"role"` // Added role field
	Timestamp       time.Time  `json:"timestamp"`
	ProtocolVersion string     `json:"protocol_version"`
	PublicKey       []byte     `json:"public_key"`
}

// NodePortConfig defines port assignments for a node.
type NodePortConfig struct {
	Name      string   // Node name (e.g., Node-0, Node-1)
	Role      NodeRole // Node role (sender, receiver, validator)
	TCPAddr   string   // TCP address (e.g., 127.0.0.1:30303)
	HTTPPort  string   // HTTP port (e.g., 127.0.0.1:8545)
	WSPort    string   // WebSocket port (e.g., 127.0.0.1:8546)
	SeedNodes []string // Seed node addresses (e.g., [127.0.0.1:30304, 127.0.0.1:30305])
}
