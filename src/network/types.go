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
	"encoding/hex"
	"sync"
	"time"

	"github.com/holiman/uint256"
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
	RoleSender    NodeRole = "sender"
	RoleReceiver  NodeRole = "receiver"
	RoleValidator NodeRole = "validator"
	RoleNone      NodeRole = "none"
)

// NodeID is a 256-bit identifier for Kademlia DHT.
type NodeID [32]byte

// String converts the NodeID to a hexadecimal string representation.
func (id NodeID) String() string {
	return hex.EncodeToString(id[:])
}

// KBucket represents a Kademlia bucket for peers at a specific distance range.
type KBucket struct {
	Peers       []*Peer
	LastUpdated time.Time
}

// NodeManager manages nodes and their peers.
type NodeManager struct {
	mu          sync.RWMutex // Unexported mutex
	nodes       map[string]*Node
	peers       map[string]*Peer
	seenMsgs    map[string]bool
	kBuckets    [256][]*KBucket
	LocalNodeID NodeID
	K           int
	ResponseCh  chan []*Peer
	PingTimeout time.Duration
}

// Node represents a participant in the blockchain or P2P network.
type Node struct {
	ID         string
	KademliaID NodeID
	Address    string
	IP         string
	Port       string
	UDPPort    string
	Status     NodeStatus
	Role       NodeRole
	LastSeen   time.Time
	IsLocal    bool
	PublicKey  []byte
	PrivateKey []byte
}

// Peer represents a directly connected node in the network.
type Peer struct {
	Node             *Node
	ConnectionStatus string
	ConnectedAt      time.Time
	LastPing         time.Time
	LastPong         time.Time
	LastSeen         time.Time
}

// PeerInfo is a shareable snapshot of peer metadata.
type PeerInfo struct {
	NodeID          string     `json:"node_id"`
	KademliaID      NodeID     `json:"kademlia_id"`
	Address         string     `json:"address"`
	IP              string     `json:"ip"`
	Port            string     `json:"port"`
	UDPPort         string     `json:"udp_port"`
	Status          NodeStatus `json:"status"`
	Role            NodeRole   `json:"role"`
	Timestamp       time.Time  `json:"timestamp"`
	ProtocolVersion string     `json:"protocol_version"`
	PublicKey       []byte     `json:"public_key"`
}

// NodePortConfig defines port assignments for a node.
type NodePortConfig struct {
	Name      string
	Role      NodeRole
	TCPAddr   string
	UDPPort   string
	HTTPPort  string
	WSPort    string
	SeedNodes []string
}

// DiscoveryMessage represents a UDP discovery message.
type DiscoveryMessage struct {
	Type       string       `json:"type"`
	Data       []byte       `json:"data"`      // Changed from interface{} to []byte
	Signature  []byte       `json:"signature"` // Add Signature field
	PublicKey  []byte       `json:"public_key"`
	MerkleRoot *uint256.Int // Changed from []byte to *uint256.Int
	Proof      []byte       `json:"proof"`
	Nonce      []byte       `json:"nonce"`
	Timestamp  []byte       `json:"timestamp"`
}

// PingData for PING messages.
type PingData struct {
	FromID    NodeID    `json:"from_id"`
	ToID      NodeID    `json:"to_id"`
	Timestamp time.Time `json:"timestamp"`
	Nonce     []byte    `json:"nonce"`
}

// PongData for PONG messages.
type PongData struct {
	FromID    NodeID    `json:"from_id"`
	ToID      NodeID    `json:"to_id"`
	Timestamp time.Time `json:"timestamp"`
	Nonce     []byte    `json:"nonce"`
}

// FindNodeData for FINDNODE messages.
type FindNodeData struct {
	TargetID  NodeID    `json:"target_id"`
	Timestamp time.Time `json:"timestamp"`
	Nonce     []byte    `json:"nonce"`
}

// NeighborsData for NEIGHBORS messages.
type NeighborsData struct {
	Nodes     []PeerInfo `json:"nodes"`
	Timestamp time.Time  `json:"timestamp"`
	Nonce     []byte     `json:"nonce"`
}

// Lock locks the NodeManager's mutex.
func (nm *NodeManager) Lock() {
	nm.mu.Lock()
}

// Unlock unlocks the NodeManager's mutex.
func (nm *NodeManager) Unlock() {
	nm.mu.Unlock()
}

// RLock read-locks the NodeManager's mutex.
func (nm *NodeManager) RLock() {
	nm.mu.RLock()
}

// RUnlock read-unlocks the NodeManager's mutex.
func (nm *NodeManager) RUnlock() {
	nm.mu.RUnlock()
}
