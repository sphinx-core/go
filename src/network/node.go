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
	"crypto/sha256"
	"fmt"
	"log"
	"time"

	key "github.com/sphinx-core/go/src/core/sphincs/key/backend"
)

// NewNode creates a new node with the specified parameters.
func NewNode(address, ip, port, udpPort string, isLocal bool, role NodeRole) *Node {
	km, err := key.NewKeyManager()
	if err != nil {
		log.Printf("Failed to create key manager: %v", err)
		return nil
	}
	sk, pk, err := km.GenerateKey()
	if err != nil {
		log.Printf("Failed to generate key pair: %v", err)
		return nil
	}
	skBytes, pkBytes, err := km.SerializeKeyPair(sk, pk)
	if err != nil {
		log.Printf("Failed to serialize key pair: %v", err)
		return nil
	}
	log.Printf("Generated keys for node %s: PrivateKey length=%d, PublicKey length=%d", address, len(skBytes), len(pkBytes))

	node := &Node{
		ID:         fmt.Sprintf("Node-%s", address),
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

func (n *Node) GenerateNodeID() NodeID {
	hash := sha256.Sum256(n.PublicKey)
	return NodeID(hash)
}

func (n *Node) UpdateStatus(status NodeStatus) {
	n.Status = status
	n.LastSeen = time.Now()
	log.Printf("Node %s (Role=%s) status updated to %s", n.ID, n.Role, status)
}

func (n *Node) UpdateRole(role NodeRole) {
	n.Role = role
	log.Printf("Node %s updated role to %s", n.ID, role)
}

func NewPeer(node *Node) *Peer {
	return &Peer{
		Node:             node,
		ConnectionStatus: "disconnected",
		ConnectedAt:      time.Time{},
		LastPing:         time.Time{},
		LastPong:         time.Time{},
	}
}

func (p *Peer) ConnectPeer() error {
	if p.Node.Status != NodeStatusActive {
		return fmt.Errorf("cannot connect to node %s: status is %s", p.Node.ID, p.Node.Status)
	}
	p.ConnectionStatus = "connected"
	p.ConnectedAt = time.Now()
	log.Printf("Peer %s (Role=%s) connected at %s", p.Node.ID, p.Node.Role, p.ConnectedAt)
	return nil
}

func (p *Peer) DisconnectPeer() {
	p.ConnectionStatus = "disconnected"
	p.ConnectedAt = time.Time{}
	p.LastPing = time.Time{}
	p.LastPong = time.Time{}
	log.Printf("Peer %s (Role=%s) disconnected", p.Node.ID, p.Node.Role)
}

func (p *Peer) SendPing() {
	p.LastPing = time.Now()
	log.Printf("Sent PING to peer %s (Role=%s)", p.Node.ID, p.Node.Role)
}

func (p *Peer) ReceivePong() {
	p.LastPong = time.Now()
	log.Printf("Received PONG from peer %s (Role=%s)", p.Node.ID, p.Node.Role)
}

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

func GenerateKademliaID(address string) NodeID {
	hash := sha256.Sum256([]byte(address))
	return NodeID(hash)
}
