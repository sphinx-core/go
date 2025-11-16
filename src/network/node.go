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

// go/src/network/node.go
package network

import (
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/sphinx-core/go/src/consensus"
	sphincsKey "github.com/sphinx-core/go/src/core/sphincs/key/backend"
)

// Add chain identification constants
const (
	SphinxChainID       = 7331
	SphinxChainName     = "Sphinx"
	SphinxSymbol        = "SPX"
	SphinxBIP44CoinType = 7331
	SphinxMagicNumber   = 0x53504858 // "SPHX"
	SphinxDefaultPort   = 32307
)

// Add method to Node for chain identification
func (n *Node) GetChainInfo() map[string]interface{} {
	return map[string]interface{}{
		"chain_id":        SphinxChainID,
		"chain_name":      SphinxChainName,
		"symbol":          SphinxSymbol,
		"bip44_coin_type": SphinxBIP44CoinType,
		"magic_number":    SphinxMagicNumber,
		"default_port":    SphinxDefaultPort,
		"node_id":         n.ID,
		"node_role":       n.Role,
	}
}

// GenerateChainHandshake generates handshake message with chain identification
func (n *Node) GenerateChainHandshake() string {
	chainInfo := n.GetChainInfo()
	return fmt.Sprintf(
		"SPHINX_HANDSHAKE\n"+
			"Chain: %s\n"+
			"Chain ID: %d\n"+
			"Node: %s\n"+
			"Role: %s\n"+
			"Protocol: 1.0.0\n"+
			"Timestamp: %d",
		chainInfo["chain_name"],
		chainInfo["chain_id"],
		n.ID,
		n.Role,
		time.Now().Unix(),
	)
}

// Global registry for tracking consensus instances across all nodes
// This is used for message broadcasting in test environments
var (
	// consensusRegistry stores all active consensus instances keyed by node ID
	consensusRegistry = make(map[string]*consensus.Consensus)
	// registryMu provides thread-safe access to the consensus registry
	registryMu sync.RWMutex
)

// CallPeer represents a peer node in the consensus call system
// Implements the consensus.Peer interface for test environments
type CallPeer struct{ id string }

// GetNode returns the node associated with this call peer
func (p *CallPeer) GetNode() consensus.Node {
	return &CallNode{id: p.id}
}

// CallNode represents a node in the consensus call system
// Implements the consensus.Node interface for test environments
type CallNode struct{ id string }

// GetID returns the unique identifier for this call node
func (n *CallNode) GetID() string {
	return n.id
}

// GetRole returns the role of this call node (always validator in test environment)
func (n *CallNode) GetRole() consensus.NodeRole {
	return consensus.RoleValidator
}

// GetStatus returns the status of this call node (always active in test environment)
func (n *CallNode) GetStatus() consensus.NodeStatus {
	return consensus.NodeStatusActive
}

// CallNodeManager manages call nodes and provides broadcast functionality
// This is used in test environments to simulate network communication
// CallNodeManager manages call nodes and provides broadcast functionality
type CallNodeManager struct {
	// Use proper peer storage with node ID as key and CallPeer as value
	peers map[string]consensus.Peer
	mu    sync.Mutex
}

// NewCallNodeManager creates a new call node manager instance
// Returns a pointer to an initialized CallNodeManager
// NewCallNodeManager creates a new call node manager instance
func NewCallNodeManager() *CallNodeManager {
	return &CallNodeManager{
		peers: make(map[string]consensus.Peer),
	}
}

// GetPeers returns all registered peers as consensus.Peer interfaces
func (m *CallNodeManager) GetPeers() map[string]consensus.Peer {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Return a copy of the peers map
	peers := make(map[string]consensus.Peer)
	for id, peer := range m.peers {
		peers[id] = peer
	}
	return peers
}

// GetPeerIDs returns the list of peer IDs for debugging
func (m *CallNodeManager) GetPeerIDs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	ids := make([]string, 0, len(m.peers))
	for id := range m.peers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// GetNode retrieves a specific node by its ID
// Returns a consensus.Node interface for the requested node
func (m *CallNodeManager) GetNode(nodeID string) consensus.Node {
	return &CallNode{id: nodeID}
}

// BroadcastMessage broadcasts consensus messages to all registered nodes
// This simulates network broadcast in test environments and delivers messages
// to all consensus instances including the sender (necessary for PBFT)
func (m *CallNodeManager) BroadcastMessage(messageType string, data interface{}) error {
	// Acquire read lock to safely access the consensus registry
	registryMu.RLock()
	defer registryMu.RUnlock()

	log.Printf("[CALL] Broadcasting %s message to %d peers", messageType, len(consensusRegistry))

	deliveredCount := 0
	var wg sync.WaitGroup

	// Deliver message to ALL consensus instances including self
	// This is required for PBFT to work correctly in test environment
	for nodeID, cons := range consensusRegistry {
		wg.Add(1)
		// Process each consensus instance in a separate goroutine
		go func(c *consensus.Consensus, typ string, d interface{}, nid string) {
			defer wg.Done()

			var err error
			// Route message based on type and call appropriate handler
			switch typ {
			case "proposal":
				prop, ok := d.(*consensus.Proposal)
				if !ok {
					log.Printf("[CALL] Invalid proposal type: %T", d)
					return
				}
				log.Printf("[CALL] Delivering proposal to %s from %s", nid, prop.ProposerID)
				err = c.HandleProposal(prop)

			case "prepare":
				vote, ok := d.(*consensus.Vote)
				if !ok {
					log.Printf("[CALL] Invalid prepare vote type: %T", d)
					return
				}
				log.Printf("[CALL] Delivering prepare vote to %s from %s", nid, vote.VoterID)
				err = c.HandlePrepareVote(vote)

			case "vote":
				vote, ok := d.(*consensus.Vote)
				if !ok {
					log.Printf("[CALL] Invalid commit vote type: %T", d)
					return
				}
				log.Printf("[CALL] Delivering commit vote to %s from %s", nid, vote.VoterID)
				err = c.HandleVote(vote)

			case "timeout":
				timeout, ok := d.(*consensus.TimeoutMsg)
				if !ok {
					log.Printf("[CALL] Invalid timeout type: %T", d)
					return
				}
				log.Printf("[CALL] Delivering timeout to %s from %s", nid, timeout.VoterID)
				err = c.HandleTimeout(timeout)

			default:
				log.Printf("[CALL] Unknown message type: %s", typ)
				return
			}

			// Log delivery result
			if err != nil {
				log.Printf("[CALL] Failed to deliver %s to %s: %v", typ, nid, err)
			} else {
				log.Printf("[CALL] Successfully delivered %s to %s", typ, nid)
				deliveredCount++
			}
		}(cons, messageType, data, nodeID)
	}

	// Wait for all message deliveries to complete
	wg.Wait()
	log.Printf("[CALL] Broadcast completed: %d/%d successful deliveries for %s",
		deliveredCount, len(consensusRegistry), messageType)

	return nil
}

// AddPeer registers a new peer node with the call node manager
func (m *CallNodeManager) AddPeer(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if peer already exists
	if _, exists := m.peers[id]; exists {
		log.Printf("[CALL] Peer %s already exists, skipping duplicate", id)
		return
	}

	// Create new peer and add to map
	m.peers[id] = &CallPeer{id: id}
	log.Printf("[CALL] Added peer: %s (total peers: %d)", id, len(m.peers))
}

// RemovePeer unregisters a peer node from the call node manager
func (m *CallNodeManager) RemovePeer(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.peers, id)
	log.Printf("[CALL] Removed peer: %s", id)
}

// RegisterConsensus adds a consensus instance to the global registry
// This allows the consensus instance to receive broadcast messages
func RegisterConsensus(nodeID string, cons *consensus.Consensus) {
	registryMu.Lock()
	defer registryMu.Unlock()
	consensusRegistry[nodeID] = cons
	log.Printf("Registered consensus for node %s", nodeID)
}

// UnregisterConsensus removes a consensus instance from the global registry
// This should be called when a consensus instance is shutting down
func UnregisterConsensus(nodeID string) {
	registryMu.Lock()
	defer registryMu.Unlock()
	delete(consensusRegistry, nodeID)
	log.Printf("Unregistered consensus for node %s", nodeID)
}

// GetConsensusRegistry returns the current consensus registry
// Primarily used for testing and debugging purposes
func GetConsensusRegistry() map[string]*consensus.Consensus {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return consensusRegistry
}

// NewNode creates a new node with the specified parameters
// Generates cryptographic keys and initializes node with provided configuration
func NewNode(address, ip, port, udpPort string, isLocal bool, role NodeRole) *Node {
	// Generate node ID from address or create one from UDP port if address is empty
	nodeID := fmt.Sprintf("Node-%s", address)
	if address == "" {
		nodeID = fmt.Sprintf("Node-%s", GenerateKademliaID(udpPort).String()[:8])
	}

	// Initialize key manager for cryptographic operations
	km, err := sphincsKey.NewKeyManager()
	if err != nil {
		log.Printf("Failed to create key manager: %v", err)
		return nil
	}

	// Generate key pair for the node
	sk, pk, err := km.GenerateKey()
	if err != nil {
		log.Printf("Failed to generate key pair: %v", err)
		return nil
	}

	// Serialize keys for storage and transmission
	skBytes, pkBytes, err := km.SerializeKeyPair(sk, pk)
	if err != nil {
		log.Printf("Failed to serialize key pair: %v", err)
		return nil
	}

	log.Printf("Generated keys for node %s: PrivateKey length=%d, PublicKey length=%d",
		address, len(skBytes), len(pkBytes))

	// Create and initialize the node instance
	node := &Node{
		ID:         nodeID,
		Address:    address,
		IP:         ip,
		Port:       port,
		UDPPort:    udpPort,
		KademliaID: GenerateKademliaID(address),
		PrivateKey: skBytes,
		PublicKey:  pkBytes,
		IsLocal:    isLocal,
		Role:       role,
		Status:     NodeStatusActive,
	}
	return node
}

// GenerateNodeID creates a node ID from the node's public key
// Uses Kademlia ID generation for consistent node identification
func (n *Node) GenerateNodeID() NodeID {
	return GenerateKademliaID(string(n.PublicKey))
}

// UpdateStatus updates the node's status and last seen timestamp
// Used for node health monitoring and network management
func (n *Node) UpdateStatus(status NodeStatus) {
	n.Status = status
	n.LastSeen = time.Now()
	log.Printf("Node %s (Role=%s) status updated to %s", n.ID, n.Role, status)
}

// UpdateRole changes the node's role in the network
// Allows dynamic role assignment during node operation
func (n *Node) UpdateRole(role NodeRole) {
	n.Role = role
	log.Printf("Node %s updated role to %s", n.ID, role)
}

// NewPeer creates a new peer instance from a node
// Initializes connection state with default values
func NewPeer(node *Node) *Peer {
	return &Peer{
		Node:             node,
		ConnectionStatus: "disconnected",
		ConnectedAt:      time.Time{},
		LastPing:         time.Time{},
		LastPong:         time.Time{},
	}
}

// ConnectPeer establishes a connection to the peer
// Returns error if the node is not in active status
func (p *Peer) ConnectPeer() error {
	if p.Node.Status != NodeStatusActive {
		return fmt.Errorf("cannot connect to node %s: status is %s", p.Node.ID, p.Node.Status)
	}
	p.ConnectionStatus = "connected"
	p.ConnectedAt = time.Now()
	log.Printf("Peer %s (Role=%s) connected at %s", p.Node.ID, p.Node.Role, p.ConnectedAt)
	return nil
}

// DisconnectPeer terminates the connection to the peer
// Resets all connection-related timestamps
func (p *Peer) DisconnectPeer() {
	p.ConnectionStatus = "disconnected"
	p.ConnectedAt = time.Time{}
	p.LastPing = time.Time{}
	p.LastPong = time.Time{}
	log.Printf("Peer %s (Role=%s) disconnected", p.Node.ID, p.Node.Role)
}

// SendPing sends a ping message to the peer
// Updates the last ping timestamp for connection health monitoring
func (p *Peer) SendPing() {
	p.LastPing = time.Now()
	log.Printf("Sent PING to peer %s (Role=%s)", p.Node.ID, p.Node.Role)
}

// ReceivePong processes a pong response from the peer
// Updates the last pong timestamp for connection health monitoring
func (p *Peer) ReceivePong() {
	p.LastPong = time.Now()
	log.Printf("Received PONG from peer %s (Role=%s)", p.Node.ID, p.Node.Role)
}

// GetPeerInfo returns comprehensive information about the peer
// Used for peer discovery, monitoring, and network diagnostics
func (p *Peer) GetPeerInfo() PeerInfo {
	return PeerInfo{
		NodeID:          p.Node.ID,
		KademliaID:      p.Node.KademliaID,
		Address:         p.Node.Address,
		IP:              p.Node.IP,
		Port:            p.Node.Port,
		UDPPort:         p.Node.UDPPort,
		Status:          p.Node.Status,
		Role:            p.Node.Role,
		Timestamp:       time.Now(),
		ProtocolVersion: "1.0",
		PublicKey:       p.Node.PublicKey,
	}
}
