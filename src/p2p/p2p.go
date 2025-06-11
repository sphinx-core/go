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

// go/src/p2p/p2p.go
package p2p

import (
	"log"
	"sync"

	"github.com/sphinx-core/go/src/core"
	types "github.com/sphinx-core/go/src/core/transaction"
	"github.com/sphinx-core/go/src/network"
	"github.com/sphinx-core/go/src/security"
	"github.com/sphinx-core/go/src/transport"
)

// Server manages the P2P network.
type Server struct {
	localNode   *network.Node
	nodeManager *network.NodeManager
	seedNodes   []string
	messageCh   chan *security.Message
	blockchain  *core.Blockchain
	mu          sync.Mutex
}

// NewServer creates a new P2P server.
func NewServer(address, ip, port string, seedNodes []string, blockchain *core.Blockchain) *Server {
	localNode := network.NewNode(address, ip, port, true)
	nodeManager := network.NewNodeManager()
	nodeManager.AddNode(localNode)
	return &Server{
		localNode:   localNode,
		nodeManager: nodeManager,
		seedNodes:   seedNodes,
		messageCh:   make(chan *security.Message, 100),
		blockchain:  blockchain,
	}
}

// Start initializes the P2P network.
func (s *Server) Start() error {
	go s.handleMessages()
	log.Printf("P2P server started, local node: ID=%s, Address=%s", s.localNode.ID, s.localNode.Address)
	return s.DiscoverPeers()
}

// handleMessages processes incoming messages.
func (s *Server) handleMessages() {
	for msg := range s.messageCh {
		log.Printf("Received message: Type=%s, Data=%v", msg.Type, msg.Data)
		switch msg.Type {
		case "transaction":
			if tx, ok := msg.Data.(*types.Transaction); ok {
				if err := s.blockchain.AddTransaction(tx); err != nil {
					log.Printf("Failed to add transaction: %v", err)
				}
			} else {
				log.Printf("Invalid transaction data")
			}
		case "block":
			if block, ok := msg.Data.(types.Block); ok {
				if err := s.blockchain.AddBlock(); err != nil {
					log.Printf("Failed to add block: %v", err)
				}
				s.Broadcast(&security.Message{Type: "block", Data: block})
			} else {
				log.Printf("Invalid block data")
			}
		case "ping":
			// Respond to PING with PONG
			if peer, ok := s.nodeManager.GetPeers()[msg.Data.(string)]; ok {
				peer.ReceivePong()
				s.Broadcast(&security.Message{Type: "pong", Data: s.localNode.ID})
			}
		case "pong":
			// Update peer’s PONG timestamp
			if peer, ok := s.nodeManager.GetPeers()[msg.Data.(string)]; ok {
				peer.ReceivePong()
			}
		case "peer_info":
			if peerInfo, ok := msg.Data.(network.PeerInfo); ok {
				node := network.NewNode(peerInfo.Address, peerInfo.IP, peerInfo.Port, false)
				node.UpdateStatus(peerInfo.Status)
				s.nodeManager.AddNode(node)
				log.Printf("Received PeerInfo: NodeID=%s, Address=%s", peerInfo.NodeID, peerInfo.Address)
			}
		default:
			log.Printf("Unknown message type: %s", msg.Type)
		}
		s.Broadcast(msg)
	}
}

// Broadcast sends a message to all peers.
func (s *Server) Broadcast(msg *security.Message) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, peer := range s.nodeManager.GetPeers() {
		if peer.ConnectionStatus != "connected" {
			continue
		}
		if msg.Type == "ping" || msg.Type == "pong" {
			// Update ping/pong timestamps
			if msg.Type == "ping" {
				peer.SendPing()
			}
			if err := transport.SendMessage(peer.Node.Address, msg); err != nil {
				log.Printf("Failed to send %s to %s: %v", msg.Type, peer.Node.Address, err)
			}
		} else if msg.Type == "peer_info" {
			if err := transport.SendPeerInfo(peer.Node.Address, msg.Data.(*network.PeerInfo)); err != nil {
				log.Printf("Failed to send PeerInfo to %s: %v", peer.Node.Address, err)
			}
		} else {
			if err := transport.SendMessage(peer.Node.Address, msg); err != nil {
				log.Printf("Failed to send to %s: %v", peer.Node.Address, err)
			}
		}
	}
}
