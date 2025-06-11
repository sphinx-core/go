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
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	key "github.com/sphinx-core/go/src/core/sphincs/key/backend"
)

// NewNode creates a new node instance with SPHINCS+ public/private keys.
// It initializes the key manager, generates the key pair, serializes the keys,
// and constructs the Node structure.
func NewNode(address, ip, port string, isLocal bool) *Node {
	// Initialize SPHINCS+ KeyManager
	km, err := key.NewKeyManager()
	if err != nil {
		log.Fatalf("Failed to initialize SPHINCS+ key manager: %v", err)
	}

	// Generate SPHINCS+ key pair
	sk, pk, err := km.GenerateKey()
	if err != nil {
		log.Fatalf("Failed to generate SPHINCS+ key pair: %v", err)
	}

	// Serialize the key pair to byte slices
	skBytes, pkBytes, err := km.SerializeKeyPair(sk, pk)
	if err != nil {
		log.Fatalf("Failed to serialize SPHINCS+ key pair: %v", err)
	}

	// Construct and return the new node with keys and metadata
	return &Node{
		ID:         uuid.New().String(), // Generate a unique identifier for the node
		Address:    address,             // Node's network address
		IP:         ip,                  // IP address of the node
		Port:       port,                // Port number
		Status:     NodeStatusUnknown,   // Initial status of the node
		LastSeen:   time.Now(),          // Timestamp of last activity
		IsLocal:    isLocal,             // Indicates if this is the local node
		PublicKey:  pkBytes,             // SPHINCS+ public key (shared with others)
		PrivateKey: skBytes,             // SPHINCS+ private key (kept secret, used locally)
	}
}

// UpdateStatus sets the node's status and updates the timestamp.
// This is typically called when a node becomes active or inactive.
func (n *Node) UpdateStatus(status NodeStatus) {
	n.Status = status
	n.LastSeen = time.Now()
	log.Printf("Node %s status updated to %s", n.ID, status)
}

// NewPeer constructs a new Peer from a Node.
// Initially, the peer is disconnected and has no ping/pong timestamps.
func NewPeer(node *Node) *Peer {
	return &Peer{
		Node:             node,
		ConnectionStatus: "disconnected", // Initial state
		ConnectedAt:      time.Time{},    // Zero value; not connected yet
		LastPing:         time.Time{},    // No ping sent yet
		LastPong:         time.Time{},    // No pong received yet
	}
}

// ConnectPeer sets the peer as connected, if the node is active.
// It also timestamps the connection time.
func (p *Peer) ConnectPeer() error {
	if p.Node.Status != NodeStatusActive {
		return fmt.Errorf("cannot connect to node %s: status is %s", p.Node.ID, p.Node.Status)
	}
	p.ConnectionStatus = "connected"
	p.ConnectedAt = time.Now()
	log.Printf("Peer %s connected at %s", p.Node.ID, p.ConnectedAt)
	return nil
}

// DisconnectPeer marks a peer as disconnected and clears connection-related timestamps.
func (p *Peer) DisconnectPeer() {
	p.ConnectionStatus = "disconnected"
	p.ConnectedAt = time.Time{}
	p.LastPing = time.Time{}
	p.LastPong = time.Time{}
	log.Printf("Peer %s disconnected", p.Node.ID)
}

// SendPing records the time a ping was sent to the peer.
func (p *Peer) SendPing() {
	p.LastPing = time.Now()
	log.Printf("Sent PING to peer %s", p.Node.ID)
}

// ReceivePong records the time a pong response was received from the peer.
func (p *Peer) ReceivePong() {
	p.LastPong = time.Now()
	log.Printf("Received PONG from peer %s", p.Node.ID)
}

// GetPeerInfo returns a serializable summary of the peer.
// This can be used for network discovery and status sharing.
func (p *Peer) GetPeerInfo() PeerInfo {
	return PeerInfo{
		NodeID:          p.Node.ID,        // Unique identifier
		Address:         p.Node.Address,   // Network address
		IP:              p.Node.IP,        // IP address
		Port:            p.Node.Port,      // Port number
		Status:          p.Node.Status,    // Node status
		Timestamp:       time.Now(),       // Timestamp of this info snapshot
		ProtocolVersion: "1.0",            // Version of the protocol
		PublicKey:       p.Node.PublicKey, // SPHINCS+ public key
	}
}
