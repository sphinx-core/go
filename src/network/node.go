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
)

// NewNode creates a new node with the given address and IP configuration.
func NewNode(address, ip, port string, isLocal bool) *Node {
	return &Node{
		ID:       uuid.New().String(),
		Address:  address,
		IP:       ip,
		Port:     port,
		Status:   NodeStatusUnknown,
		LastSeen: time.Now(),
		IsLocal:  isLocal,
	}
}

// UpdateStatus updates the node's status and last seen timestamp.
func (n *Node) UpdateStatus(status NodeStatus) {
	n.Status = status
	n.LastSeen = time.Now()
	log.Printf("Node %s status updated to %s", n.ID, status)
}

// NewPeer creates a new peer from a node.
func NewPeer(node *Node) *Peer {
	return &Peer{
		Node:             node,
		ConnectionStatus: "disconnected",
		ConnectedAt:      time.Time{},
		LastPing:         time.Time{},
		LastPong:         time.Time{},
	}
}

// ConnectPeer marks a peer as connected.
func (p *Peer) ConnectPeer() error {
	if p.Node.Status != NodeStatusActive {
		return fmt.Errorf("cannot connect to node %s: status is %s", p.Node.ID, p.Node.Status)
	}
	p.ConnectionStatus = "connected"
	p.ConnectedAt = time.Now()
	log.Printf("Peer %s connected at %s", p.Node.ID, p.ConnectedAt)
	return nil
}

// DisconnectPeer marks a peer as disconnected.
func (p *Peer) DisconnectPeer() {
	p.ConnectionStatus = "disconnected"
	p.ConnectedAt = time.Time{}
	p.LastPing = time.Time{}
	p.LastPong = time.Time{}
	log.Printf("Peer %s disconnected", p.Node.ID)
}

// SendPing updates the last ping timestamp.
func (p *Peer) SendPing() {
	p.LastPing = time.Now()
	log.Printf("Sent PING to peer %s", p.Node.ID)
}

// ReceivePong updates the last pong timestamp.
func (p *Peer) ReceivePong() {
	p.LastPong = time.Now()
	log.Printf("Received PONG from peer %s", p.Node.ID)
}

// GetPeerInfo generates PeerInfo for the peer.
func (p *Peer) GetPeerInfo() PeerInfo {
	return PeerInfo{
		NodeID:          p.Node.ID,
		Address:         p.Node.Address,
		IP:              p.Node.IP,
		Port:            p.Node.Port,
		Status:          p.Node.Status,
		Timestamp:       time.Now(),
		ProtocolVersion: "1.0", // Adjust as needed
	}
}
