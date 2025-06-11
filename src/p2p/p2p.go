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
	"fmt"
	"log"
	"sync"
	"time"

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
	localNode := network.NewNode(address, ip, port, true, network.RoleNone)
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

// LocalNode returns the local node of the server.
func (s *Server) LocalNode() *network.Node {
	return s.localNode
}

// NodeManager returns the node manager of the server.
func (s *Server) NodeManager() *network.NodeManager {
	return s.nodeManager
}

// Start initializes the P2P network.
func (s *Server) Start() error {
	go s.handleMessages()
	log.Printf("P2P server started, local node: ID=%s, Address=%s, Role=%s", s.localNode.ID, s.localNode.Address, s.localNode.Role)
	// Delay peer discovery to ensure TCP servers are ready
	time.Sleep(5 * time.Second)
	return s.DiscoverPeers()
}

// handleMessages processes incoming messages.
func (s *Server) handleMessages() {
	for msg := range s.messageCh {
		log.Printf("Received message: Type=%s, Data=%v", msg.Type, msg.Data)
		switch msg.Type {
		case "transaction":
			if tx, ok := msg.Data.(*types.Transaction); ok {
				s.assignTransactionRoles(tx)
				if err := s.validateTransaction(tx); err != nil {
					log.Printf("Transaction validation failed: %v", err)
					continue
				}
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
			if peer, ok := s.nodeManager.GetPeers()[msg.Data.(string)]; ok {
				peer.ReceivePong()
				s.Broadcast(&security.Message{Type: "pong", Data: s.localNode.ID})
			}
		case "pong":
			if peer, ok := s.nodeManager.GetPeers()[msg.Data.(string)]; ok {
				peer.ReceivePong()
			}
		case "peer_info":
			if peerInfo, ok := msg.Data.(network.PeerInfo); ok {
				node := network.NewNode(peerInfo.Address, peerInfo.IP, peerInfo.Port, false, peerInfo.Role)
				node.UpdateStatus(peerInfo.Status)
				s.nodeManager.AddNode(node)
				log.Printf("Received PeerInfo: NodeID=%s, Address=%s, Role=%s", peerInfo.NodeID, peerInfo.Address, peerInfo.Role)
			}
		default:
			log.Printf("Unknown message type: %s", msg.Type)
		}
		s.Broadcast(msg)
	}
}

// assignTransactionRoles assigns Sender and Receiver roles based on transaction.
func (s *Server) assignTransactionRoles(tx *types.Transaction) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, node := range s.nodeManager.GetPeers() {
		if node.Node.Address == tx.Sender {
			node.Node.UpdateRole(network.RoleSender)
		} else if node.Node.Address == tx.Receiver {
			node.Node.UpdateRole(network.RoleReceiver)
			if _, exists := s.nodeManager.GetPeers()[node.Node.ID]; !exists {
				if err := s.nodeManager.AddPeer(node.Node); err != nil {
					log.Printf("Failed to make %s a peer: %v", node.Node.ID, err)
				} else {
					log.Printf("Node %s (Role=receiver) became peer for transaction", node.Node.ID)
				}
			}
		}
	}
}

// validateTransaction sends the transaction to a validator node.
func (s *Server) validateTransaction(tx *types.Transaction) error {
	validatorNode := s.nodeManager.SelectValidator()
	if validatorNode == nil {
		return fmt.Errorf("no validator available")
	}
	if _, exists := s.nodeManager.GetPeers()[validatorNode.ID]; !exists {
		if err := s.nodeManager.AddPeer(validatorNode); err != nil {
			return fmt.Errorf("failed to connect to validator %s: %v", validatorNode.ID, err)
		}
		log.Printf("Node %s (Role=validator) became peer for validation", validatorNode.ID)
	}
	peer := s.nodeManager.GetPeers()[validatorNode.ID]
	if err := transport.SendMessage(peer.Node.Address, &security.Message{Type: "transaction", Data: tx}); err != nil {
		return fmt.Errorf("failed to send transaction to validator %s: %v", validatorNode.ID, err)
	}
	log.Printf("Transaction sent to validator %s for validation", validatorNode.ID)
	return nil
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
			if msg.Type == "ping" {
				peer.SendPing()
			}
			if err := transport.SendMessage(peer.Node.Address, msg); err != nil {
				log.Printf("Failed to send %s to %s (Role=%s): %v", msg.Type, peer.Node.Address, peer.Node.Role, err)
			}
		} else if msg.Type == "peer_info" {
			if err := transport.SendPeerInfo(peer.Node.Address, msg.Data.(*network.PeerInfo)); err != nil {
				log.Printf("Failed to send PeerInfo to %s (Role=%s): %v", peer.Node.Address, peer.Node.Role, err)
			}
		} else {
			if err := transport.SendMessage(peer.Node.Address, msg); err != nil {
				log.Printf("Failed to send to %s (Role=%s): %v", peer.Node.Address, peer.Node.Role, err)
			}
		}
	}
}
