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
	"time"

	"github.com/google/uuid"
	key "github.com/sphinx-core/go/src/core/sphincs/key/backend"
)

// NewNode creates a new node instance with SPHINCS+ keys.
func NewNode(address, ip, port string, isLocal bool, role NodeRole) *Node {
	km, err := key.NewKeyManager()
	if err != nil {
		log.Fatalf("Failed to initialize SPHINCS+ key manager: %v", err)
	}
	sk, pk, err := km.GenerateKey()
	if err != nil {
		log.Fatalf("Failed to generate SPHINCS+ key pair: %v", err)
	}
	skBytes, pkBytes, err := km.SerializeKeyPair(sk, pk)
	if err != nil {
		log.Fatalf("Failed to serialize SPHINCS+ key pair: %v", err)
	}
	return &Node{
		ID:         uuid.New().String(),
		Address:    address,
		IP:         ip,
		Port:       port,
		Status:     NodeStatusUnknown,
		Role:       role, // Set initial role
		LastSeen:   time.Now(),
		IsLocal:    isLocal,
		PublicKey:  pkBytes,
		PrivateKey: skBytes,
	}
}

// UpdateStatus sets the node's status and updates the timestamp.
func (n *Node) UpdateStatus(status NodeStatus) {
	n.Status = status
	n.LastSeen = time.Now()
	log.Printf("Node %s (Role=%s) status updated to %s", n.ID, n.Role, status)
}

// UpdateRole updates the node's role.
func (n *Node) UpdateRole(role NodeRole) {
	n.Role = role
	log.Printf("Node %s updated role to %s", n.ID, role)
}

// NewPeer constructs a new Peer from a Node.
func NewPeer(node *Node) *Peer {
	return &Peer{
		Node:             node,
		ConnectionStatus: "disconnected",
		ConnectedAt:      time.Time{},
		LastPing:         time.Time{},
		LastPong:         time.Time{},
	}
}

// ConnectPeer sets the peer as connected if the node is active.
func (p *Peer) ConnectPeer() error {
	if p.Node.Status != NodeStatusActive {
		return fmt.Errorf("cannot connect to node %s: status is %s", p.Node.ID, p.Node.Status)
	}
	p.ConnectionStatus = "connected"
	p.ConnectedAt = time.Now()
	log.Printf("Peer %s (Role=%s) connected at %s", p.Node.ID, p.Node.Role, p.ConnectedAt)
	return nil
}

// DisconnectPeer marks a peer as disconnected.
func (p *Peer) DisconnectPeer() {
	p.ConnectionStatus = "disconnected"
	p.ConnectedAt = time.Time{}
	p.LastPing = time.Time{}
	p.LastPong = time.Time{}
	log.Printf("Peer %s (Role=%s) disconnected", p.Node.ID, p.Node.Role)
}

// SendPing records the time a ping was sent.
func (p *Peer) SendPing() {
	p.LastPing = time.Now()
	log.Printf("Sent PING to peer %s (Role=%s)", p.Node.ID, p.Node.Role)
}

// ReceivePong records the time a pong was received.
func (p *Peer) ReceivePong() {
	p.LastPong = time.Now()
	log.Printf("Received PONG from peer %s (Role=%s)", p.Node.ID, p.Node.Role)
}

// GetPeerInfo returns a serializable peer summary.
func (p *Peer) GetPeerInfo() PeerInfo {
	return PeerInfo{
		NodeID:          p.Node.ID,
		Address:         p.Node.Address,
		IP:              p.Node.IP,
		Port:            p.Node.Port,
		Status:          p.Node.Status,
		Role:            p.Node.Role,
		Timestamp:       time.Now(),
		ProtocolVersion: "1.0",
		PublicKey:       p.Node.PublicKey,
	}
}
