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
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/sphinx-core/go/src/core"
	types "github.com/sphinx-core/go/src/core/transaction"
	"github.com/sphinx-core/go/src/network"
	"github.com/sphinx-core/go/src/security"
	"github.com/sphinx-core/go/src/transport"
)

// NewServer creates a new P2P server.
func NewServer(address, ip, port string, seedNodes []string, blockchain *core.Blockchain) *Server {
	localNode := network.NewNode(address, ip, port, true, network.RoleNone)
	nodeManager := network.NewNodeManager()
	nodeManager.AddNode(localNode)
	server := &Server{
		localNode:   localNode,
		nodeManager: nodeManager,
		seedNodes:   seedNodes,
		messageCh:   make(chan *security.Message, 100),
		blockchain:  blockchain,
	}
	server.peerManager = NewPeerManager(server)
	return server
}

// Start initializes the P2P network.
func (s *Server) Start() error {
	log.Printf("Initializing P2P server for node %s", s.localNode.Address)
	go s.handleMessages()
	go s.peerManager.MaintainPeers()
	log.Printf("P2P server started, local node: ID=%s, Address=%s, Role=%s", s.localNode.ID, s.localNode.Address, s.localNode.Role)
	time.Sleep(5 * time.Second)
	log.Printf("Starting peer discovery for node %s", s.localNode.Address)
	if err := s.DiscoverPeers(); err != nil {
		log.Printf("Peer discovery failed for node %s: %v", s.localNode.Address, err)
		return err
	}
	log.Printf("Peer discovery completed for node %s", s.localNode.Address)
	return nil
}

// handleMessages processes incoming messages.
func (s *Server) handleMessages() {
	for msg := range s.messageCh {
		log.Printf("Received message: Type=%s, Data=%v", msg.Type, msg.Data)
		originID := "" // Simplified: track origin if needed

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
					if originID != "" {
						s.peerManager.UpdatePeerScore(originID, -10)
					}
					continue
				}
				s.peerManager.PropagateMessage(msg, originID)
				if originID != "" {
					s.peerManager.UpdatePeerScore(originID, 5)
				}
			} else {
				log.Printf("Invalid transaction data")
			}

		case "block":
			if block, ok := msg.Data.(types.Block); ok {
				// Add block transactions to pending pool
				for _, tx := range block.Body.TxsList {
					if err := s.blockchain.AddTransaction(tx); err != nil {
						log.Printf("Failed to add block transaction %s: %v", tx.ID, err)
						if originID != "" {
							s.peerManager.UpdatePeerScore(originID, -5)
						}
						continue // Skip to next transaction
					}
				}
				// Create new block from pending transactions
				if err := s.blockchain.AddBlock(); err != nil {
					log.Printf("Failed to create block: %v", err)
					if originID != "" {
						s.peerManager.UpdatePeerScore(originID, -10)
					}
					continue
				}
				s.peerManager.PropagateMessage(msg, originID)
				if originID != "" {
					s.peerManager.UpdatePeerScore(originID, 10)
				}
			} else {
				log.Printf("Invalid block data")
			}

		case "ping":
			if peerID, ok := msg.Data.(string); ok {
				if peer, ok := s.nodeManager.GetPeers()[peerID]; ok {
					peer.ReceivePong()
					s.Broadcast(&security.Message{Type: "pong", Data: s.localNode.ID})
					s.peerManager.UpdatePeerScore(peerID, 2)
				}
			}

		case "pong":
			if peerID, ok := msg.Data.(string); ok {
				if peer, ok := s.nodeManager.GetPeers()[peerID]; ok {
					peer.ReceivePong()
					s.peerManager.UpdatePeerScore(peerID, 2)
				}
			}

		case "peer_info":
			if peerInfo, ok := msg.Data.(network.PeerInfo); ok {
				node := network.NewNode(peerInfo.Address, peerInfo.IP, peerInfo.Port, false, peerInfo.Role)
				node.UpdateStatus(peerInfo.Status)
				s.nodeManager.AddNode(node)
				s.peerManager.ConnectPeer(node)
				log.Printf("Received PeerInfo: NodeID=%s, Address=%s, Role=%s", peerInfo.NodeID, peerInfo.Address, peerInfo.Role)
			}

		case "version":
			if versionData, ok := msg.Data.(map[string]interface{}); ok {
				peerID, ok := versionData["node_id"].(string)
				if !ok {
					log.Printf("Invalid node_id in version message")
					continue
				}
				verackMsg := &security.Message{Type: "verack", Data: s.localNode.ID}
				if peer, ok := s.nodeManager.GetPeers()[peerID]; ok {
					transport.SendMessage(peer.Node.Address, verackMsg)
					s.peerManager.UpdatePeerScore(peerID, 5)
				}
			}

		case "verack":
			if peerID, ok := msg.Data.(string); ok {
				s.peerManager.UpdatePeerScore(peerID, 5)
			}

		case "getheaders":
			if data, ok := msg.Data.(map[string]interface{}); ok {
				startHeight, ok := data["start_height"].(float64)
				if !ok {
					log.Printf("Invalid start_height in getheaders")
					continue
				}
				blocks := s.blockchain.GetBlocks()
				var headers []types.BlockHeader
				for _, block := range blocks {
					if block.Header.Block >= uint64(startHeight) {
						headers = append(headers, block.Header)
					}
				}
				if peer, ok := s.nodeManager.GetPeers()[originID]; ok && originID != "" {
					transport.SendMessage(peer.Node.Address, &security.Message{
						Type: "headers",
						Data: headers,
					})
				}
			}

		case "headers":
			if headers, ok := msg.Data.([]types.BlockHeader); ok {
				log.Printf("Received %d headers from peer %s", len(headers), originID)
				if originID != "" {
					s.peerManager.UpdatePeerScore(originID, 10)
				}
			}

		default:
			log.Printf("Unknown message type: %s", msg.Type)
			if originID != "" {
				s.peerManager.UpdatePeerScore(originID, -5)
			}
		}
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
					log.Printf("Node %s (receiver) became peer for transaction", node.Node.ID)
				}
			}
		}
	}
}

// validateTransaction sends a transaction to a validator node.
func (s *Server) validateTransaction(tx *types.Transaction) error {
	validatorNode := s.nodeManager.SelectValidator()
	if validatorNode == nil {
		return errors.New("no validator available")
	}
	if _, exists := s.nodeManager.GetPeers()[validatorNode.ID]; !exists {
		if err := s.peerManager.ConnectPeer(validatorNode); err != nil {
			return fmt.Errorf("failed to connect to validator %s: %v", validatorNode.ID, err)
		}
		log.Printf("Node %s (validator) became peer for validation", validatorNode.ID)
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
	s.peerManager.PropagateMessage(msg, s.localNode.ID)
}
