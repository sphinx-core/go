// MIT License
//
// # Copyright (c) 2024 sphinx-core
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

// go/src/p2p/peer.go
package p2p

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"strings"
	"time"

	"github.com/sphinx-core/go/src/network"
	"github.com/sphinx-core/go/src/security"
	"github.com/sphinx-core/go/src/transport"
)

// NewPeerManager creates a new peer manager.
func NewPeerManager(server *Server) *PeerManager {
	return &PeerManager{
		server:      server,
		peers:       make(map[string]*network.Peer),
		scores:      make(map[string]int),
		bans:        make(map[string]time.Time),
		maxPeers:    50, // Configurable limit
		maxInbound:  30, // Configurable limit
		maxOutbound: 20, // Configurable limit
	}
}

// ConnectPeer establishes a connection to a peer and performs handshake.
func (pm *PeerManager) ConnectPeer(node *network.Node) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Check if banned
	if banExpiry, banned := pm.bans[node.ID]; banned && time.Now().Before(banExpiry) {
		return fmt.Errorf("peer %s is banned until %v", node.ID, banExpiry)
	}

	// Check peer limits
	if len(pm.peers) >= pm.maxPeers {
		return errors.New("maximum peer limit reached")
	}

	// Connect via transport
	if err := transport.ConnectNode(node, pm.server.messageCh); err != nil {
		return fmt.Errorf("failed to connect to %s: %v", node.ID, err)
	}

	// Perform version handshake
	if err := pm.performHandshake(node); err != nil {
		transport.DisconnectNode(node)
		return fmt.Errorf("handshake failed with %s: %v", node.ID, err)
	}

	// Add peer
	peer := &network.Peer{
		Node:             node,
		ConnectionStatus: "connected",
		ConnectedAt:      time.Now(),
		LastSeen:         time.Now(),
	}
	if err := pm.server.nodeManager.AddPeer(node); err != nil {
		transport.DisconnectNode(node)
		return fmt.Errorf("failed to add peer %s: %v", node.ID, err)
	}
	pm.peers[node.ID] = peer
	pm.scores[node.ID] = 50 // Initial score
	log.Printf("Connected to peer %s (Role=%s)", node.ID, node.Role)

	// Send initial messages
	peer.SendPing()
	pm.server.Broadcast(&security.Message{Type: "peer_info", Data: network.PeerInfo{
		NodeID:  pm.server.localNode.ID,
		Address: pm.server.localNode.Address,
		IP:      pm.server.localNode.IP,
		Port:    pm.server.localNode.Port,
		Role:    pm.server.localNode.Role,
		Status:  network.NodeStatusActive,
	}})

	return nil
}

// performHandshake negotiates protocol version and capabilities.
func (pm *PeerManager) performHandshake(node *network.Node) error {
	nonce := make([]byte, 8)
	rand.Read(nonce)
	versionMsg := &security.Message{
		Type: "version",
		Data: map[string]interface{}{
			"version":      "0.1.0",
			"node_id":      pm.server.localNode.ID,
			"chain_id":     "sphinx-mainnet",
			"block_height": pm.server.blockchain.GetBlockCount(),
			"nonce":        hex.EncodeToString(nonce),
		},
	}
	if err := transport.SendMessage(node.Address, versionMsg); err != nil {
		return err
	}
	time.Sleep(1 * time.Second) // Placeholder for response
	return nil
}

// DisconnectPeer terminates a peer connection.
func (pm *PeerManager) DisconnectPeer(peerID string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	peer, exists := pm.peers[peerID]
	if !exists {
		return fmt.Errorf("peer %s not found", peerID)
	}

	if err := transport.DisconnectNode(peer.Node); err != nil {
		log.Printf("Failed to disconnect peer %s: %v", peerID, err)
	}

	delete(pm.peers, peerID)
	delete(pm.scores, peerID)
	pm.server.nodeManager.RemovePeer(peerID)
	log.Printf("Disconnected peer %s", peerID)
	return nil
}

// BanPeer bans a peer for misbehavior.
func (pm *PeerManager) BanPeer(peerID string, duration time.Duration) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if _, exists := pm.peers[peerID]; !exists {
		return fmt.Errorf("peer %s not found", peerID)
	}

	pm.bans[peerID] = time.Now().Add(duration)
	return pm.DisconnectPeer(peerID)
}

// UpdatePeerScore adjusts a peer’s score based on behavior.
func (pm *PeerManager) UpdatePeerScore(peerID string, delta int) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if _, exists := pm.peers[peerID]; !exists {
		return
	}
	pm.scores[peerID] += delta
	if pm.scores[peerID] < 0 {
		pm.scores[peerID] = 0
		pm.BanPeer(peerID, 1*time.Hour)
	} else if pm.scores[peerID] > 100 {
		pm.scores[peerID] = 100
	}
	log.Printf("Updated score for peer %s: %d", peerID, pm.scores[peerID])
}

// PropagateMessage implements gossip protocol for message propagation.
func (pm *PeerManager) PropagateMessage(msg *security.Message, originID string) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// Deduplicate messages
	msgID := generateMessageID(msg)
	if pm.server.nodeManager.HasSeenMessage(msgID) {
		return
	}
	pm.server.nodeManager.MarkMessageSeen(msgID)

	// Select top-scoring peers for propagation
	type peerScore struct {
		peer  *network.Peer
		score int
	}
	var candidates []peerScore
	for id, peer := range pm.peers {
		if id == originID || peer.ConnectionStatus != "connected" {
			continue
		}
		candidates = append(candidates, peerScore{peer, pm.scores[id]})
	}

	// Sort by score (descending)
	for i := 0; i < len(candidates)-1; i++ {
		for j := i + 1; j < len(candidates); j++ {
			if candidates[i].score < candidates[j].score {
				candidates[i], candidates[j] = candidates[j], candidates[i]
			}
		}
	}

	// Propagate to top N peers
	n := int(math.Sqrt(float64(len(candidates))))
	if n < 3 {
		n = 3
	} else if n > 10 {
		n = 10
	}
	for i := 0; i < n && i < len(candidates); i++ {
		peer := candidates[i].peer
		if err := transport.SendMessage(peer.Node.Address, msg); err != nil {
			log.Printf("Failed to propagate %s to %s: %v", msg.Type, peer.Node.ID, err)
			pm.UpdatePeerScore(peer.Node.ID, -10)
		} else {
			pm.UpdatePeerScore(peer.Node.ID, 5)
		}
	}
}

// SyncBlockchain synchronizes the blockchain with a peer.
func (pm *PeerManager) SyncBlockchain(peerID string) error {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	peer, exists := pm.peers[peerID]
	if !exists {
		return fmt.Errorf("peer %s not found", peerID)
	}

	headersMsg := &security.Message{
		Type: "getheaders",
		Data: map[string]interface{}{
			"start_height": pm.server.blockchain.GetBlockCount(),
		},
	}
	if err := transport.SendMessage(peer.Node.Address, headersMsg); err != nil {
		return fmt.Errorf("failed to request headers from %s: %v", peerID, err)
	}

	log.Printf("Requested headers from peer %s", peerID)
	return nil
}

// MaintainPeers ensures optimal peer connections.
func (pm *PeerManager) MaintainPeers() {
	for {
		pm.mu.Lock()
		// Evict low-scoring peers
		for id, score := range pm.scores {
			if score < 20 && len(pm.peers) > pm.maxPeers/2 {
				pm.DisconnectPeer(id)
			}
		}

		// Connect to new peers if needed
		if len(pm.peers) < pm.maxPeers/2 {
			for _, addr := range pm.server.seedNodes {
				if _, exists := pm.peers[addr]; exists || addr == pm.server.localNode.Address {
					continue
				}
				parts := strings.Split(addr, ":")
				if len(parts) != 2 {
					continue
				}
				node := network.NewNode(addr, parts[0], parts[1], false, network.RoleNone)
				go pm.ConnectPeer(node)
			}
		}
		pm.mu.Unlock()
		time.Sleep(30 * time.Second)
	}
}

// generateMessageID creates a unique ID for a message.
func generateMessageID(msg *security.Message) string {
	data, _ := json.Marshal(msg)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
