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

package network

import (
	"sync"
	"time"
)

// NodeStatus represents the operational state of a node in the network.
type NodeStatus string

const (
	// NodeStatusActive indicates the node is currently online and reachable.
	NodeStatusActive NodeStatus = "active"

	// NodeStatusInactive indicates the node was previously seen but is not currently reachable.
	NodeStatusInactive NodeStatus = "inactive"

	// NodeStatusUnknown is used when the node's status is not yet determined.
	NodeStatusUnknown NodeStatus = "unknown"
)

// NodeManager manages nodes and their peers.
type NodeManager struct {
	nodes map[string]*Node // All known nodes, keyed by Node.ID
	peers map[string]*Peer // Connected peers, keyed by Node.ID
	mu    sync.RWMutex     // Thread safety for node and peer access
}

// Node represents a participant in the blockchain or P2P network.
// Each node holds a unique identity, network details, and a key pair for secure communication.
type Node struct {
	ID         string     // Unique identifier (UUID) for the node
	Address    string     // User-friendly network address (e.g., domain or hostname)
	IP         string     // IP address of the node
	Port       string     // Port number the node listens on
	Status     NodeStatus // Current status of the node (active/inactive/unknown)
	LastSeen   time.Time  // Timestamp when the node was last seen or interacted with
	IsLocal    bool       // True if this node is the local instance
	PublicKey  []byte     // Serialized SPHINCS+ public key (shared with others)
	PrivateKey []byte     // Serialized SPHINCS+ private key (used only locally)
}

// Peer represents a directly connected node in the network.
// This tracks connection and ping/pong timestamps for liveness checks.
type Peer struct {
	Node             *Node     // Reference to the associated node
	ConnectionStatus string    // Connection state (e.g., connected, disconnected)
	ConnectedAt      time.Time // Timestamp when the connection was established
	LastPing         time.Time // Timestamp when the last ping was sent
	LastPong         time.Time // Timestamp when the last pong was received
}

// PeerInfo is a compact, shareable snapshot of peer metadata.
// Used for peer discovery and network topology exchange.
type PeerInfo struct {
	NodeID          string     `json:"node_id"`          // Unique identifier of the peer node
	Address         string     `json:"address"`          // Friendly address or domain
	IP              string     `json:"ip"`               // IP address of the peer
	Port            string     `json:"port"`             // Port number for communication
	Status          NodeStatus `json:"status"`           // Current known status of the peer
	Timestamp       time.Time  `json:"timestamp"`        // Timestamp when this info was generated
	ProtocolVersion string     `json:"protocol_version"` // Version of the communication protocol
	PublicKey       []byte     `json:"public_key"`       // Serialized SPHINCS+ public key for verification
}
