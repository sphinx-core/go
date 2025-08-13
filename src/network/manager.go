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
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

// NewNodeManager creates a new NodeManager with Kademlia buckets and a DHT implementation.
func NewNodeManager(bucketSize int, dht DHT) *NodeManager {
	if bucketSize <= 0 {
		bucketSize = 16 // Standard default size for Kademlia k=16
	}
	return &NodeManager{
		nodes:       make(map[string]*Node),
		peers:       make(map[string]*Peer),
		seenMsgs:    make(map[string]bool),
		kBuckets:    [256][]*KBucket{},
		K:           bucketSize,
		PingTimeout: 5 * time.Second,
		ResponseCh:  make(chan []*Peer, 100),
		DHT:         dht, // Initialize DHT
	}
}

// AddNode adds a new node to the manager and updates k-buckets.
func (nm *NodeManager) AddNode(node *Node) {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	// Check for existing node by ID or KademliaID
	if existingNode, exists := nm.nodes[node.ID]; exists && existingNode.KademliaID == node.KademliaID {
		// Update existing node's attributes
		existingNode.Address = node.Address
		existingNode.IP = node.IP
		existingNode.Port = node.Port
		existingNode.UDPPort = node.UDPPort
		existingNode.Role = node.Role
		existingNode.Status = node.Status
		existingNode.LastSeen = time.Now()
		log.Printf("Updated existing node: ID=%s, Address=%s, Role=%s, KademliaID=%x", node.ID, node.Address, node.Role, node.KademliaID[:8])
		return
	}

	// Check for existing node by KademliaID (in case ID differs)
	for _, n := range nm.nodes {
		if n.KademliaID == node.KademliaID && n.ID != node.ID {
			// Update the existing node's ID and other attributes
			delete(nm.nodes, n.ID) // Remove old ID mapping
			n.ID = node.ID
			n.Address = node.Address
			n.IP = node.IP
			n.Port = node.Port
			n.UDPPort = node.UDPPort
			n.Role = node.Role
			n.Status = node.Status
			n.LastSeen = time.Now()
			nm.nodes[node.ID] = n
			log.Printf("Updated node with matching KademliaID: ID=%s, Address=%s, Role=%s, KademliaID=%x", node.ID, node.Address, node.Role, node.KademliaID[:8])
			return
		}
	}

	// Add new node to nodes map
	nm.nodes[node.ID] = node

	// Add to appropriate k-bucket if not local node
	if !node.IsLocal {
		distance := nm.CalculateDistance(nm.LocalNodeID, node.KademliaID)
		bucketIndex := nm.logDistance(distance)
		if bucketIndex >= 0 && bucketIndex < 256 {
			if nm.kBuckets[bucketIndex] == nil {
				nm.kBuckets[bucketIndex] = make([]*KBucket, 0)
			}
			// Check if node already exists in k-bucket
			for _, b := range nm.kBuckets[bucketIndex] {
				for _, p := range b.Peers {
					if p.Node.ID == node.ID || p.Node.KademliaID == node.KademliaID {
						// Update existing peer's node attributes
						p.Node = node
						b.LastUpdated = time.Now()
						log.Printf("Updated peer in k-bucket: ID=%s, Address=%s, Role=%s, KademliaID=%x", node.ID, node.Address, node.Role, node.KademliaID[:8])
						return
					}
				}
				if len(b.Peers) < nm.K {
					b.Peers = append(b.Peers, NewPeer(node))
					b.LastUpdated = time.Now()
					log.Printf("Added node to k-bucket: ID=%s, Address=%s, Role=%s, KademliaID=%x", node.ID, node.Address, node.Role, node.KademliaID[:8])
					return
				}
				// Bucket is full, try to evict an inactive peer
				if evicted := nm.evictInactivePeer(b, node); evicted {
					return
				}
			}
			// No space in existing buckets, create a new one
			nm.kBuckets[bucketIndex] = append(nm.kBuckets[bucketIndex], &KBucket{
				Peers:       []*Peer{NewPeer(node)},
				LastUpdated: time.Now(),
			})
			log.Printf("Created new k-bucket for node: ID=%s, Address=%s, Role=%s, KademliaID=%x", node.ID, node.Address, node.Role, node.KademliaID[:8])
		}
	}
	log.Printf("Added node: ID=%s, Address=%s, Role=%s, KademliaID=%x", node.ID, node.Address, node.Role, node.KademliaID[:8])
}

// UpdateNode updates the attributes of an existing node.
func (nm *NodeManager) UpdateNode(node *Node) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	existingNode, exists := nm.nodes[node.ID]
	if !exists {
		return fmt.Errorf("node %s not found", node.ID)
	}
	existingNode.Address = node.Address
	existingNode.IP = node.IP
	existingNode.Port = node.Port
	existingNode.UDPPort = node.UDPPort
	existingNode.Role = node.Role
	existingNode.Status = node.Status
	existingNode.LastSeen = node.LastSeen
	if node.KademliaID != [32]byte{} {
		existingNode.KademliaID = node.KademliaID
	}
	distance := nm.CalculateDistance(nm.LocalNodeID, existingNode.KademliaID)
	bucketIndex := nm.logDistance(distance)
	if bucketIndex >= 0 && bucketIndex < 256 {
		for _, bucket := range nm.kBuckets[bucketIndex] {
			for _, peer := range bucket.Peers {
				if peer.Node.ID == node.ID {
					peer.Node = existingNode
					bucket.LastUpdated = time.Now()
					log.Printf("Updated node in k-bucket: ID=%s, Address=%s, Role=%s, KademliaID=%x", node.ID, node.Address, node.Role, node.KademliaID[:8])
					break
				}
			}
		}
	}
	if peer, ok := nm.peers[node.ID]; ok {
		peer.Node = existingNode
		peer.LastSeen = node.LastSeen
		log.Printf("Updated peer: ID=%s, Address=%s, Role=%s", node.ID, node.Address, node.Role)
	}
	log.Printf("Updated node: ID=%s, Address=%s, Role=%s, KademliaID=%x", node.ID, node.Address, node.Role, node.KademliaID[:8])
	return nil
}

// evictInactivePeer attempts to evict an inactive peer from a bucket.
func (nm *NodeManager) evictInactivePeer(bucket *KBucket, newNode *Node) bool {
	// Find the least recently seen peer
	var oldestPeer *Peer
	var oldestIndex int
	minTime := time.Now()
	for i, peer := range bucket.Peers {
		if peer.LastPong.Before(minTime) {
			minTime = peer.LastPong
			oldestPeer = peer
			oldestIndex = i
		}
	}
	if oldestPeer == nil {
		return false
	}
	// Ping the oldest peer to check liveness
	if nm.pingPeer(oldestPeer) {
		return false // Peer is still active
	}
	// Evict the oldest peer and add the new node
	bucket.Peers = append(bucket.Peers[:oldestIndex], bucket.Peers[oldestIndex+1:]...)
	bucket.Peers = append(bucket.Peers, NewPeer(newNode))
	bucket.LastUpdated = time.Now()
	log.Printf("Evicted inactive peer %s, added new node %s", oldestPeer.Node.ID, newNode.ID)
	return true
}

// pingPeer sends a ping and waits for a pong response.
func (nm *NodeManager) pingPeer(peer *Peer) bool {
	peer.SendPing()
	addr, err := net.ResolveUDPAddr("udp", peer.Node.UDPPort)
	if err != nil {
		log.Printf("Failed to resolve UDP address for peer %s: %v", peer.Node.ID, err)
		return false
	}
	nm.DHT.PingNode(peer.Node.KademliaID, *addr)
	time.Sleep(10 * time.Second) // Increase timeout
	return !peer.LastPong.IsZero() && time.Since(peer.LastPong) < 10*time.Second
}

// RemoveNode removes a node and its peer entry.
func (nm *NodeManager) RemoveNode(nodeID string) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	if node, exists := nm.nodes[nodeID]; exists {
		delete(nm.nodes, nodeID)
		delete(nm.peers, nodeID)
		distance := nm.CalculateDistance(nm.LocalNodeID, node.KademliaID)
		bucketIndex := nm.logDistance(distance)
		if bucketIndex >= 0 && bucketIndex < 256 {
			for i, bucket := range nm.kBuckets[bucketIndex] {
				for j, peer := range bucket.Peers {
					if peer.Node.ID == nodeID {
						bucket.Peers = append(bucket.Peers[:j], bucket.Peers[j+1:]...)
						bucket.LastUpdated = time.Now()
						if len(bucket.Peers) == 0 {
							nm.kBuckets[bucketIndex] = append(nm.kBuckets[bucketIndex][:i], nm.kBuckets[bucketIndex][i+1:]...)
						}
						break
					}
				}
			}
		}
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
	for id, node := range nm.nodes {
		if time.Since(node.LastSeen) > timeout && !node.IsLocal {
			nm.RemoveNode(id)
		}
	}
	for i, buckets := range nm.kBuckets {
		for j, bucket := range buckets {
			if time.Since(bucket.LastUpdated) > time.Hour {
				nm.kBuckets[i] = append(nm.kBuckets[i][:j], nm.kBuckets[i][j+1:]...)
			}
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
	if node.IP == "" || node.Port == "" {
		log.Printf("Cannot add peer %s: empty IP or port", node.ID)
		return fmt.Errorf("cannot add peer %s: empty IP or port", node.ID)
	}
	// Check for existing peer by ID or KademliaID
	for _, p := range nm.peers {
		if p.Node.ID == node.ID || p.Node.KademliaID == node.KademliaID {
			log.Printf("Peer %s already exists, skipping addition", node.ID)
			return nil
		}
	}
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

// GetNodeByKademliaID returns a node by its Kademlia ID.
func (nm *NodeManager) GetNodeByKademliaID(kademliaID NodeID) *Node {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	for _, node := range nm.nodes {
		if node.KademliaID == kademliaID {
			return node
		}
	}
	return nil
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
		if peer.Node.ID != sender.Node.ID {
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

// CalculateDistance computes the XOR distance between two node IDs.
func (nm *NodeManager) CalculateDistance(id1, id2 NodeID) NodeID {
	var result NodeID
	for i := 0; i < 32; i++ {
		result[i] = id1[i] ^ id2[i]
	}
	return result
}

// logDistance returns the log2 of the distance (bucket index).
func (nm *NodeManager) logDistance(distance NodeID) int {
	for i := 31; i >= 0; i-- {
		if distance[i] != 0 {
			for bit := 7; bit >= 0; bit-- {
				if (distance[i]>>uint(bit))&1 != 0 {
					return i*8 + bit
				}
			}
		}
	}
	return 0
}

// FindClosestPeers returns the k closest peers to a target ID, randomly selecting if more than k are available.
// FindClosestPeers returns the k closest peers to a target ID, using the DHT interface.
func (nm *NodeManager) FindClosestPeers(targetID NodeID, k int) []*Peer {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	// Use DHT interface to find nearest nodes
	remotes := nm.DHT.KNearest(targetID)
	result := make([]*Peer, 0, k)

	for _, remote := range remotes {
		node := nm.GetNodeByKademliaID(remote.NodeID)
		if node == nil {
			// Parse remote.Address (format: "IP:port") to extract IP and port
			addrParts := strings.Split(remote.Address.String(), ":")
			if len(addrParts) != 2 {
				log.Printf("FindClosestPeers: Invalid remote address format %s", remote.Address.String())
				continue
			}
			port := addrParts[1] // Port number as string
			ip := addrParts[0]
			node = &Node{
				ID:         fmt.Sprintf("Node-%s", remote.NodeID.String()[:8]),
				KademliaID: remote.NodeID,
				Address:    fmt.Sprintf("%s:%d", ip, remote.Address.Port-1), // Assume TCP port is UDP port - 1
				IP:         ip,
				UDPPort:    port, // Store port number as string
				Status:     NodeStatusActive,
				Role:       RoleNone,
				LastSeen:   time.Now(),
			}
			nm.nodes[node.ID] = node
		}
		peer := NewPeer(node)
		if err := peer.ConnectPeer(); err == nil {
			nm.peers[node.ID] = peer
			result = append(result, peer)
		}
		if len(result) >= k {
			break
		}
	}
	return result
}

// CompareDistance compares two distances (returns -1, 0, or 1).
func (nm *NodeManager) CompareDistance(d1, d2 NodeID) int {
	for i := 31; i >= 0; i-- {
		if d1[i] < d2[i] {
			return -1
		} else if d1[i] > d2[i] {
			return 1
		}
	}
	return 0
}
