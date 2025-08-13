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
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"math/big"
	"net"
	"time"

	security "github.com/sphinx-core/go/src/handshake"
	"github.com/sphinx-core/go/src/network"
	"github.com/sphinx-core/go/src/transport"
)

// NewPeerManager creates a new peer manager.
func NewPeerManager(server *Server, bucketSize int) *PeerManager {
	return &PeerManager{
		server:      server,
		peers:       make(map[string]*network.Peer),
		scores:      make(map[string]int),
		bans:        make(map[string]time.Time),
		maxPeers:    50,
		maxInbound:  30,
		maxOutbound: 20,
	}
}

// ConnectPeer establishes a connection to a peer and performs handshake.
// go/src/p2p/peer.go
// ConnectPeer establishes a connection to a peer and performs handshake.
func (pm *PeerManager) ConnectPeer(node *network.Node) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if banExpiry, banned := pm.bans[node.ID]; banned && time.Now().Before(banExpiry) {
		log.Printf("Peer %s is banned until %v", node.ID, banExpiry)
		return fmt.Errorf("peer %s is banned until %v", node.ID, banExpiry)
	}
	if len(pm.peers) >= pm.maxPeers {
		log.Printf("Maximum peer limit reached: %d", pm.maxPeers)
		return errors.New("maximum peer limit reached")
	}
	log.Printf("Connecting to node %s via TCP: %s", node.ID, node.Address)
	_, err := transport.ConnectTCP(node.Address, pm.server.messageCh)
	if err != nil {
		log.Printf("Failed to connect to %s: %v", node.ID, err)
		return fmt.Errorf("failed to connect to %s: %v", node.ID, err)
	}
	log.Printf("TCP connection established to %s", node.Address)

	// Add peer to nodeManager.peers before handshake
	peer := &network.Peer{
		Node:             node,
		ConnectionStatus: "connected",
		ConnectedAt:      time.Now(),
		LastSeen:         time.Now(),
	}
	if err := pm.server.nodeManager.AddPeer(node); err != nil {
		log.Printf("Failed to add peer %s: %v", node.ID, err)
		transport.DisconnectNode(node) // This will close the connection
		return fmt.Errorf("failed to add peer %s: %v", node.ID, err)
	}
	pm.peers[node.ID] = peer
	pm.scores[node.ID] = 50

	// Perform handshake after adding peer
	if err := pm.performHandshake(node); err != nil {
		log.Printf("Handshake failed with %s: %v", node.ID, err)
		transport.DisconnectNode(node) // This will close the connection
		pm.server.nodeManager.RemovePeer(node.ID)
		delete(pm.peers, node.ID)
		delete(pm.scores, node.ID)
		return fmt.Errorf("handshake failed with %s: %v", node.ID, err)
	}

	if err := pm.server.StorePeer(peer); err != nil {
		log.Printf("Failed to store peer %s in DB: %v", node.ID, err)
	}
	log.Printf("Connected to peer %s (Role=%s)", node.ID, node.Role)
	peer.SendPing()
	pm.server.Broadcast(&security.Message{Type: "peer_info", Data: network.PeerInfo{
		NodeID:          pm.server.localNode.ID,
		KademliaID:      pm.server.localNode.KademliaID,
		Address:         pm.server.localNode.Address,
		IP:              pm.server.localNode.IP,
		Port:            pm.server.localNode.Port,
		UDPPort:         pm.server.localNode.UDPPort,
		Role:            pm.server.localNode.Role,
		Status:          network.NodeStatusActive,
		Timestamp:       time.Now(),
		ProtocolVersion: "1.0",
		PublicKey:       pm.server.localNode.PublicKey,
	}})
	return nil
}

// performHandshake negotiates protocol version and capabilities.
func (pm *PeerManager) performHandshake(node *network.Node) error {
	log.Printf("Starting handshake with %s (ID=%s)", node.Address, node.ID)

	// Add peer to nodeManager.peers before sending version message
	pm.mu.Lock()
	if _, exists := pm.peers[node.ID]; !exists {
		pm.peers[node.ID] = &network.Peer{
			Node:             node,
			ConnectionStatus: "pending",
			ConnectedAt:      time.Now(),
			LastSeen:         time.Now(),
		}
		log.Printf("Added peer %s to nodeManager.peers before handshake", node.ID)
	}
	pm.mu.Unlock()

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
			"address":      pm.server.localNode.Address,
		},
	}
	conn, err := transport.GetConnection(node.Address)
	if err != nil {
		log.Printf("No active connection to %s: %v", node.Address, err)
		return fmt.Errorf("no active connection to %s: %v", node.Address, err)
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		tcpConn.Write([]byte{}) // Flush the connection
	}
	if err := transport.SendMessage(node.Address, versionMsg); err != nil {
		log.Printf("Failed to send version message to %s: %v", node.Address, err)
		return err
	}
	log.Printf("Version message sent to %s, waiting for verack response", node.Address)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for {
		select {
		case msg := <-pm.server.messageCh:
			log.Printf("Received message in handshake for %s: Type=%s, Data=%v, ChannelLen=%d", node.Address, msg.Type, msg.Data, len(pm.server.messageCh))
			if msg.Type == "verack" {
				if peerID, ok := msg.Data.(string); ok && peerID == node.ID {
					log.Printf("Received valid verack from %s for node_id: %s, Address: %s", node.Address, peerID, node.Address)
					pm.mu.Lock()
					if peer, exists := pm.peers[node.ID]; exists {
						peer.ConnectionStatus = "active"
						peer.LastSeen = time.Now()
					} else {
						log.Printf("Peer %s not found in nodeManager.peers during verack", node.ID)
					}
					pm.mu.Unlock()
					return nil
				} else {
					log.Printf("Invalid verack from %s: peerID=%v, expected=%s, Address: %s", node.Address, msg.Data, node.ID, node.Address)
				}
			} else {
				log.Printf("Unexpected message type in handshake for %s: %s", node.Address, msg.Type)
			}
		case <-ctx.Done():
			log.Printf("Timeout waiting for verack from %s: %v", node.Address, ctx.Err())
			return fmt.Errorf("timeout waiting for verack from %s", node.Address)
		}
	}
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
	msgID := generateMessageID(msg)
	if pm.server.nodeManager.HasSeenMessage(msgID) {
		return
	}
	pm.server.nodeManager.MarkMessageSeen(msgID)
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
	// Randomly select up to sqrt(n) peers
	n := int(math.Sqrt(float64(len(candidates))))
	if n < 3 {
		n = 3
	} else if n > 10 {
		n = 10
	}
	if len(candidates) > n {
		for i := 0; i < n; i++ {
			j, _ := rand.Int(rand.Reader, big.NewInt(int64(len(candidates)-i)))
			idx := i + int(j.Int64())
			candidates[i], candidates[idx] = candidates[idx], candidates[i]
		}
		candidates = candidates[:n]
	}
	for _, candidate := range candidates {
		peer := candidate.peer
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
		for id, score := range pm.scores {
			if score < 20 && len(pm.peers) > pm.maxPeers/2 {
				pm.DisconnectPeer(id)
			}
		}
		if len(pm.peers) < pm.maxPeers/2 {
			peers := pm.server.nodeManager.FindClosestPeers(pm.server.localNode.KademliaID, pm.maxPeers-len(pm.peers))
			for _, peer := range peers {
				if _, exists := pm.peers[peer.Node.ID]; !exists && peer.Node.Address != pm.server.localNode.Address {
					go pm.ConnectPeer(peer.Node)
				}
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
