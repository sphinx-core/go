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

// go/src/network/manager.go
package network

import (
	"log"
	"time"
)

// NewNodeManager creates a new NodeManager.
func NewNodeManager() *NodeManager {
	return &NodeManager{
		nodes: make(map[string]*Node),
		peers: make(map[string]*Peer),
	}
}

// AddNode adds a new node to the manager.
func (nm *NodeManager) AddNode(node *Node) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	nm.nodes[node.ID] = node
	log.Printf("Added node: ID=%s, Address=%s, Role=%s", node.ID, node.Address, node.Role)
}

// RemoveNode removes a node and its peer entry.
func (nm *NodeManager) RemoveNode(nodeID string) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	if node, exists := nm.nodes[nodeID]; exists {
		delete(nm.nodes, nodeID)
		delete(nm.peers, nodeID)
		log.Printf("Removed node: ID=%s, Address=%s, Role=%s", nodeID, node.Address, node.Role)
	}
}

// PruneInactivePeers disconnects peers with no recent pong.
func (nm *NodeManager) PruneInactivePeers(timeout time.Duration) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	for id, peer := range nm.peers {
		if time.Since(peer.LastPong) > timeout {
			nm.RemovePeer(id)
		}
	}
}

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

// AddPeer adds a node as a peer, marking it as connected.
func (nm *NodeManager) AddPeer(node *Node) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	if _, exists := nm.nodes[node.ID]; !exists {
		nm.nodes[node.ID] = node
	}
	peer := NewPeer(node)
	if err := peer.ConnectPeer(); err != nil {
		return err
	}
	nm.peers[node.ID] = peer
	log.Printf("Node %s (Role=%s) became peer at %s", node.ID, node.Role, peer.ConnectedAt)
	return nil
}

// RemovePeer disconnects a peer.
func (nm *NodeManager) RemovePeer(nodeID string) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	if peer, exists := nm.peers[nodeID]; exists {
		peer.DisconnectPeer()
		delete(nm.peers, nodeID)
		log.Printf("Removed peer: ID=%s, Role=%s", nodeID, peer.Node.Role)
	}
}

// GetNode returns a node by its ID.
func (nm *NodeManager) GetNode(nodeID string) *Node {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	return nm.nodes[nodeID]
}

// GetPeers returns all connected peers.
func (nm *NodeManager) GetPeers() map[string]*Peer {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	peers := make(map[string]*Peer)
	for id, peer := range nm.peers {
		peers[id] = peer
	}
	return peers
}

// BroadcastPeerInfo sends PeerInfo to all connected peers.
func (nm *NodeManager) BroadcastPeerInfo(sender *Peer, sendFunc func(string, *PeerInfo) error) error {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	peerInfo := sender.GetPeerInfo()
	for _, peer := range nm.peers {
		if peer.Node.ID != sender.Node.ID { // Avoid sending to self
			if err := sendFunc(peer.Node.Address, &peerInfo); err != nil {
				log.Printf("Failed to send PeerInfo to %s (Role=%s): %v", peer.Node.ID, peer.Node.Role, err)
			}
		}
	}
	return nil
}

// SelectValidator selects a node with RoleValidator for transaction validation.
func (nm *NodeManager) SelectValidator() *Node {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	for _, node := range nm.nodes {
		if node.Role == RoleValidator && node.Status == NodeStatusActive {
			log.Printf("Selected validator: ID=%s, Address=%s", node.ID, node.Address)
			return node
		}
	}
	log.Println("No active validator found")
	return nil
}
