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
	"net"
	"sync"
	"time"

	"github.com/holiman/uint256"
	database "github.com/sphinx-core/go/src/core/state"
)

// NodeStatus represents the operational state of a node in the network.
type NodeStatus string

// NodeID represents a 256-bit identifier for Kademlia DHT.
type NodeID [32]byte

// Key represents a 256-bit key used in the DHT, matching NodeID.
type Key [32]byte

// nodeID is an alias for Key, used to represent node identifiers in the DHT.
type nodeID = Key

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
	mu          sync.RWMutex
	nodes       map[string]*Node
	peers       map[string]*Peer
	seenMsgs    map[string]bool
	kBuckets    [256][]*KBucket
	LocalNodeID NodeID
	K           int
	ResponseCh  chan []*Peer
	PingTimeout time.Duration
	DHT         DHT // Add DHT interface field
	db          *database.DB
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
	db         *database.DB // Add database reference
}

// NetworkKeyManager manages cryptographic keys for nodes
type NetworkKeyManager struct {
	db         *database.DB
	keyManager interface{} // Using interface{} since sphincsKey might not be available
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
// NodePortConfig defines the port configuration for a node.
type NodePortConfig struct {
	ID        string   `json:"id"` // Aligns with Node.ID
	Name      string   `json:"name"`
	TCPAddr   string   `json:"tcp_addr"`
	UDPPort   string   `json:"udp_port"`
	HTTPPort  string   `json:"http_port"`
	WSPort    string   `json:"ws_port"`
	Role      NodeRole `json:"role"`
	SeedNodes []string `json:"seed_nodes"`
	DHTSecret uint16   // New field
}

// DiscoveryMessage represents a UDP discovery message.
type DiscoveryMessage struct {
	Type       string       `json:"type"`
	Data       []byte       `json:"data"`
	Signature  []byte       `json:"signature"`
	PublicKey  []byte       `json:"public_key"`
	MerkleRoot *uint256.Int `json:"merkle_root"`
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

// DHT defines the interface for DHT operations used by NodeManager.
type DHT interface {
	KNearest(target NodeID) []Remote
	Put(key Key, value []byte, ttl uint16)
	Get(key Key) ([][]byte, bool)
	ScheduleGet(delay time.Duration, key Key)
	GetCached(key Key) [][]byte
	Join()
	SelfNodeID() NodeID
	PingNode(nodeID NodeID, addr net.UDPAddr)
	Close() error
	Start() error // Add Start method
}

// Remote represents a remote node in the DHT.
type Remote struct {
	NodeID  NodeID
	Address net.UDPAddr
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
