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

	"github.com/sphinx-core/go/src/common"
	sphincsKey "github.com/sphinx-core/go/src/core/sphincs/key/backend"
	database "github.com/sphinx-core/go/src/core/state"
)

// Add this method to NodeManager for chain recognition
func (nm *NodeManager) GetChainInfo() map[string]interface{} {
	return map[string]interface{}{
		"chain_id":         7331,
		"chain_name":       "Sphinx",
		"symbol":           "SPX",
		"protocol_version": "1.0.0",
		"network_magic":    "0x53504858", // "SPHX"
		"default_port":     32307,
		"bip44_coin_type":  7331,
	}
}

// GenerateNodeIdentification generates node identification with chain info
func (nm *NodeManager) GenerateNodeIdentification(nodeID string) string {
	chainInfo := nm.GetChainInfo()
	return fmt.Sprintf(
		"Sphinx Node: %s\n"+
			"Network: %s\n"+
			"Chain ID: %d\n"+
			"Protocol: %s\n"+
			"User Agent: SphinxNode/%s",
		nodeID,
		chainInfo["chain_name"],
		chainInfo["chain_id"],
		chainInfo["protocol_version"],
		chainInfo["protocol_version"],
	)
}

// ValidateChainCompatibility checks if remote node is compatible with Sphinx chain
func (nm *NodeManager) ValidateChainCompatibility(remoteChainInfo map[string]interface{}) bool {
	localInfo := nm.GetChainInfo()

	// Check chain ID compatibility
	remoteChainID, ok := remoteChainInfo["chain_id"].(int)
	if !ok {
		return false
	}

	return remoteChainID == localInfo["chain_id"]
}

// EXISTING FUNCTIONS CONTINUE UNCHANGED...
// NewNodeManager creates a new NodeManager with Kademlia buckets and a DHT implementation.
// Update NodeManager constructor
func NewNodeManager(bucketSize int, dht DHT, db *database.DB) *NodeManager {
	if bucketSize <= 0 {
		bucketSize = 16
	}
	return &NodeManager{
		nodes:       make(map[string]*Node),
		peers:       make(map[string]*Peer),
		seenMsgs:    make(map[string]bool),
		kBuckets:    [256][]*KBucket{},
		K:           bucketSize,
		PingTimeout: 10 * time.Second,
		ResponseCh:  make(chan []*Peer, 100),
		DHT:         dht,
		db:          db, // Add database reference
	}
}

// Add method to create local node with database
func (nm *NodeManager) CreateLocalNode(address, ip, port, udpPort string, role NodeRole) error {
	localNode := NewNode(address, ip, port, udpPort, true, role, nm.db)
	if localNode == nil {
		return fmt.Errorf("failed to create local node")
	}

	nm.LocalNodeID = localNode.KademliaID
	nm.AddNode(localNode)

	log.Printf("Created local node: ID=%s, Role=%s, Keys stored in database", localNode.ID, role)
	return nil
}

// Update BackupNodeInfo to use config directory
func (nm *NodeManager) BackupNodeInfo(node *Node) error {
	nodeData := map[string]interface{}{
		"id":          node.ID,
		"address":     node.Address,
		"ip":          node.IP,
		"port":        node.Port,
		"udp_port":    node.UDPPort,
		"kademlia_id": node.KademliaID[:],
		"role":        string(node.Role),
		"status":      string(node.Status),
		"last_seen":   node.LastSeen.Format(time.RFC3339),
		"public_key":  node.PublicKey,
	}

	// Store in config directory
	if err := common.WriteNodeInfo(node.ID, nodeData); err != nil {
		return fmt.Errorf("failed to backup node info to config directory: %w", err)
	}

	// Also store in database for backward compatibility
	data, err := serializeNodeData(nodeData)
	if err != nil {
		return fmt.Errorf("failed to serialize node data: %w", err)
	}

	key := fmt.Sprintf("node_info:%s", node.ID)
	if err := nm.db.Put(key, data); err != nil {
		return fmt.Errorf("failed to backup node info to database: %w", err)
	}

	return nil
}

// Update RestoreNodeFromDB to also check config directory
func (nm *NodeManager) RestoreNodeFromDB(nodeID string) (*Node, error) {
	// First try to restore from config directory
	node, err := nm.restoreNodeFromConfig(nodeID)
	if err == nil {
		log.Printf("Restored node %s from config directory", nodeID)
		return node, nil
	}

	log.Printf("Failed to restore node %s from config directory: %v, trying database", nodeID, err)

	// Fall back to database
	key := fmt.Sprintf("node_info:%s", nodeID)
	data, err := nm.db.Get(key)
	if err != nil {
		return nil, fmt.Errorf("failed to load node info from database: %w", err)
	}

	nodeData, err := deserializeNodeData(data)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize node data: %w", err)
	}

	// Load keys from config directory first, then database
	privateKey, publicKey, err := loadNodeKeysFromConfig(nodeID)
	if err != nil {
		log.Printf("Failed to load keys from config directory: %v, trying database", err)
		privateKey, publicKey, err = loadNodeKeys(nm.db, nodeID)
		if err != nil {
			return nil, fmt.Errorf("failed to load node keys: %w", err)
		}
	}

	// Reconstruct node
	node = &Node{
		ID:         nodeData["id"].(string),
		Address:    nodeData["address"].(string),
		IP:         nodeData["ip"].(string),
		Port:       nodeData["port"].(string),
		UDPPort:    nodeData["udp_port"].(string),
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		IsLocal:    false, // Restored nodes are not local
		Role:       NodeRole(nodeData["role"].(string)),
		Status:     NodeStatusActive, // Start as active
		db:         nm.db,
	}

	// Restore Kademlia ID
	if kademliaID, ok := nodeData["kademlia_id"].([]byte); ok {
		copy(node.KademliaID[:], kademliaID)
	}

	// Restore last seen
	if lastSeenStr, ok := nodeData["last_seen"].(string); ok {
		if lastSeen, err := time.Parse(time.RFC3339, lastSeenStr); err == nil {
			node.LastSeen = lastSeen
		}
	}

	return node, nil
}

// New method to restore node from config directory
func (nm *NodeManager) restoreNodeFromConfig(nodeID string) (*Node, error) {
	nodeInfo, err := common.ReadNodeInfo(nodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to read node info from config: %w", err)
	}

	privateKey, publicKey, err := loadNodeKeysFromConfig(nodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to load keys from config: %w", err)
	}

	// Reconstruct node from config data
	node := &Node{
		ID:         nodeInfo["id"].(string),
		Address:    nodeInfo["address"].(string),
		IP:         nodeInfo["ip"].(string),
		Port:       nodeInfo["port"].(string),
		UDPPort:    nodeInfo["udp_port"].(string),
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		IsLocal:    nodeInfo["is_local"].(bool),
		Role:       NodeRole(nodeInfo["role"].(string)),
		Status:     NodeStatusActive,
		db:         nm.db,
	}

	// Restore Kademlia ID if available
	if kademliaID, ok := nodeInfo["kademlia_id"].([]byte); ok {
		copy(node.KademliaID[:], kademliaID)
	} else {
		// Generate from address if not stored
		node.KademliaID = GenerateKademliaID(node.Address)
	}

	// Restore creation time if available
	if createdAtStr, ok := nodeInfo["created_at"].(string); ok {
		if createdAt, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
			node.LastSeen = createdAt
		}
	}

	return node, nil
}

// Update RotateNodeKeys to use simple key generation
func (nkm *NetworkKeyManager) RotateNodeKeys(nodeID string) error {
	// Generate new key pair using simple method
	privateKey, publicKey, err := nkm.GenerateSimpleKeys()
	if err != nil {
		return fmt.Errorf("failed to generate new key pair: %w", err)
	}

	// Serialize keys
	privateKey, publicKey, err = nkm.SerializeSimpleKeys(privateKey, publicKey)
	if err != nil {
		return fmt.Errorf("failed to serialize new key pair: %w", err)
	}

	// Store new keys with versioning (existing implementation)
	timestamp := time.Now().Unix()
	privateKeyKey := fmt.Sprintf("node:%s:private_key:%d", nodeID, timestamp)
	publicKeyKey := fmt.Sprintf("node:%s:public_key:%d", nodeID, timestamp)
	currentPrivateKey := fmt.Sprintf("node:%s:private_key:current", nodeID)
	currentPublicKey := fmt.Sprintf("node:%s:public_key:current", nodeID)

	// Store versioned keys
	if err := nkm.db.Put(privateKeyKey, privateKey); err != nil {
		return fmt.Errorf("failed to store versioned private key: %w", err)
	}
	if err := nkm.db.Put(publicKeyKey, publicKey); err != nil {
		return fmt.Errorf("failed to store versioned public key: %w", err)
	}

	// Update current key references
	if err := nkm.db.Put(currentPrivateKey, []byte(privateKeyKey)); err != nil {
		return fmt.Errorf("failed to update current private key reference: %w", err)
	}
	if err := nkm.db.Put(currentPublicKey, []byte(publicKeyKey)); err != nil {
		return fmt.Errorf("failed to update current public key reference: %w", err)
	}

	// Archive old keys
	if err := nkm.cleanupOldKeys(nodeID); err != nil {
		log.Printf("Warning: failed to cleanup old keys: %v", err)
	}

	log.Printf("Successfully rotated keys for node %s", nodeID)
	return nil
}

func NewNetworkKeyManager(db *database.DB) (*NetworkKeyManager, error) {
	km, err := sphincsKey.NewKeyManager()
	if err != nil {
		return nil, err
	}

	return &NetworkKeyManager{
		db:         db,
		keyManager: km,
	}, nil
}

// GetCurrentKeys retrieves the current active keys for a node
func (nkm *NetworkKeyManager) GetCurrentKeys(nodeID string) ([]byte, []byte, error) {
	// Get current key references
	currentPrivateKey := fmt.Sprintf("node:%s:private_key:current", nodeID)
	currentPublicKey := fmt.Sprintf("node:%s:public_key:current", nodeID)

	privateKeyRef, err := nkm.db.Get(currentPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get current private key reference: %w", err)
	}
	publicKeyRef, err := nkm.db.Get(currentPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get current public key reference: %w", err)
	}

	// Get actual keys using references
	privateKey, err := nkm.db.Get(string(privateKeyRef))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get current private key: %w", err)
	}
	publicKey, err := nkm.db.Get(string(publicKeyRef))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get current public key: %w", err)
	}

	return privateKey, publicKey, nil
}

// AddNode adds a new node to the manager and updates k-buckets.
// Around line 30 in manager.go
func (nm *NodeManager) AddNode(node *Node) {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	// Check for existing node by ID or KademliaID
	if existingNode, exists := nm.nodes[node.ID]; exists && existingNode.KademliaID == node.KademliaID {
		log.Printf("Node %s (KademliaID: %x) already exists, skipping addition", node.ID, node.KademliaID[:8])
		return
	}
	for _, n := range nm.nodes {
		if n.KademliaID == node.KademliaID && n.ID != node.ID {
			log.Printf("Node with KademliaID %x already exists as %s, skipping addition", node.KademliaID[:8], n.ID)
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
			for _, b := range nm.kBuckets[bucketIndex] {
				for _, p := range b.Peers {
					if p.Node.ID == node.ID || p.Node.KademliaID == node.KademliaID {
						log.Printf("Peer %s (KademliaID: %x) already in k-bucket, skipping addition", node.ID, node.KademliaID[:8])
						return
					}
				}
				if len(b.Peers) < nm.K {
					b.Peers = append(b.Peers, NewPeer(node))
					b.LastUpdated = time.Now()
					log.Printf("Added node to k-bucket: ID=%s, Address=%s, Role=%s, KademliaID=%x", node.ID, node.Address, node.Role, node.KademliaID[:8])
					return
				}
				if evicted := nm.evictInactivePeer(b, node); evicted {
					return
				}
			}
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
	if _, exists := nm.peers[node.ID]; exists {
		log.Printf("Peer %s already exists in peers map, skipping addition", node.ID)
		return nil
	}
	for _, p := range nm.peers {
		if p.Node.KademliaID == node.KademliaID && p.Node.ID != node.ID {
			log.Printf("Peer with KademliaID %x already exists as %s, skipping addition", node.KademliaID[:8], p.Node.ID)
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
