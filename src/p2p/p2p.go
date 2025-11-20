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
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sphinx-core/go/src/consensus"
	"github.com/sphinx-core/go/src/core"
	database "github.com/sphinx-core/go/src/core/state"
	types "github.com/sphinx-core/go/src/core/transaction"
	"github.com/sphinx-core/go/src/dht"
	security "github.com/sphinx-core/go/src/handshake"
	"github.com/sphinx-core/go/src/network"
	"github.com/sphinx-core/go/src/transport"
	"github.com/syndtr/goleveldb/leveldb"
	"go.uber.org/zap"
)

// NewServer creates a new P2P server.
func NewServer(config network.NodePortConfig, blockchain *core.Blockchain, db *leveldb.DB) *Server {
	bucketSize := 16 // Standard default size for Kademlia k=16
	parts := strings.Split(config.TCPAddr, ":")
	if len(parts) != 2 {
		log.Fatalf("Invalid TCPAddr format: %s", config.TCPAddr)
	}
	udpPort, err := strconv.Atoi(config.UDPPort)
	if err != nil {
		log.Fatalf("Invalid UDPPort format: %s, %v", config.UDPPort, err)
	}

	// Convert leveldb.DB to database.DB
	nodeDB := &database.DB{} // You'll need to adapt this based on your database interface
	// If your database.DB wraps leveldb.DB, you might need something like:
	// nodeDB := database.NewDBFromLevelDB(db)

	// FIX: Add the database parameter
	localNode := network.NewNode(config.TCPAddr, parts[0], parts[1], config.UDPPort, true, config.Role, nodeDB)

	// Initialize logger for DHT
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	// Generate or use DHT secret
	var secret uint16
	if config.DHTSecret != 0 {
		secret = config.DHTSecret
		log.Printf("Using DHT secret from config: %d", secret)
	} else {
		secretBytes := make([]byte, 2)
		if _, err := rand.Read(secretBytes); err != nil {
			log.Fatalf("Failed to generate random secret for DHT: %v", err)
		}
		secret = binary.BigEndian.Uint16(secretBytes)
	}
	// Allow override via environment variable
	if envSecret := os.Getenv("DHT_SECRET"); envSecret != "" {
		if parsedSecret, err := strconv.ParseUint(envSecret, 10, 16); err == nil {
			secret = uint16(parsedSecret)
			log.Printf("Using DHT secret from environment variable: %d", secret)
		} else {
			log.Printf("Invalid DHT_SECRET environment variable: %v, generating random secret", err)
			secretBytes := make([]byte, 2)
			if _, err := rand.Read(secretBytes); err != nil {
				log.Fatalf("Failed to generate random secret for DHT: %v", err)
			}
			secret = binary.BigEndian.Uint16(secretBytes)
		}
	} else {
		log.Printf("No DHT_SECRET provided, using config secret: %d", secret)
	}

	// Configure DHT
	dhtConfig := dht.Config{
		Proto:   "udp",
		Address: net.UDPAddr{IP: net.ParseIP(parts[0]), Port: udpPort},
		Routers: make([]net.UDPAddr, 0, len(config.SeedNodes)),
		Secret:  secret,
	}
	for _, seed := range config.SeedNodes {
		seedParts := strings.Split(seed, ":")
		if len(seedParts) == 2 {
			port, err := strconv.Atoi(seedParts[1])
			if err != nil {
				log.Printf("Invalid seed node port %s: %v", seed, err)
				continue
			}
			dhtConfig.Routers = append(dhtConfig.Routers, net.UDPAddr{
				IP:   net.ParseIP(seedParts[0]),
				Port: port,
			})
		}
	}
	dhtInstance, err := dht.NewDHT(dhtConfig, logger)
	if err != nil {
		log.Fatalf("Failed to initialize DHT: %v", err)
	}

	// FIX: Add the database parameter
	nodeManager := network.NewNodeManager(bucketSize, dhtInstance, nodeDB)

	return &Server{
		localNode:   localNode,
		nodeManager: nodeManager,
		seedNodes:   config.SeedNodes,
		dht:         dhtInstance,
		peerManager: NewPeerManager(nil, bucketSize),
		sphincsMgr:  nil,
		db:          db,
		udpReadyCh:  make(chan struct{}, 1),
		messageCh:   make(chan *security.Message, 100),
		blockchain:  blockchain,
		stopCh:      make(chan struct{}),
	}
}

// UpdateSeedNodes updates the server's seed nodes.
func (s *Server) UpdateSeedNodes(seedNodes []string) {
	s.mu.Lock()
	s.seedNodes = seedNodes
	log.Printf("UpdateSeedNodes: Set seed nodes for %s to %v", s.localNode.Address, s.seedNodes)
	s.mu.Unlock()
}

// SetServer sets the server field for the peer manager.
func (s *Server) SetServer() {
	s.peerManager.server = s
}

// Start starts the P2P server and initializes peer discovery.
func (s *Server) Start() error {
	s.SetServer() // Set server for peerManager
	if err := s.StartUDPDiscovery(s.localNode.UDPPort); err != nil {
		return fmt.Errorf("failed to start UDP discovery: %v", err)
	}
	go s.handleMessages() // Start message handler
	return nil
}

// Close shuts down the P2P server.
func (s *Server) Close() error {
	var errs []error
	if err := s.StopUDPDiscovery(); err != nil {
		errs = append(errs, fmt.Errorf("failed to stop UDP discovery: %v", err))
	}
	if s.messageCh != nil {
		select {
		case <-s.messageCh:
			// Channel already closed
		default:
			close(s.messageCh)
		}
	}
	// Allow time for sockets to release
	time.Sleep(1 * time.Second)
	if len(errs) > 0 {
		return fmt.Errorf("errors during P2P server shutdown: %v", errs)
	}
	return nil
}

// CloseDB closes the LevelDB instance.
func (s *Server) CloseDB() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// StorePeer stores peer information in LevelDB.
func (s *Server) StorePeer(peer *network.Peer) error {
	peerInfo := peer.GetPeerInfo()
	data, err := json.Marshal(peerInfo)
	if err != nil {
		return fmt.Errorf("failed to marshal peer info: %v", err)
	}
	key := []byte("peer-" + peer.Node.ID)
	return s.db.Put(key, data, nil)
}

// FetchPeer retrieves peer information from LevelDB.
func (s *Server) FetchPeer(nodeID string) (*network.PeerInfo, error) {
	key := []byte("peer-" + nodeID)
	data, err := s.db.Get(key, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch peer %s: %v", nodeID, err)
	}
	var peerInfo network.PeerInfo
	if err := json.Unmarshal(data, &peerInfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal peer info: %v", err)
	}
	return &peerInfo, nil
}

// handleMessages processes incoming messages.
func (s *Server) handleMessages() {
	for msg := range s.messageCh {
		log.Printf("Processing message from channel: Type=%s, Data=%v, ChannelLen=%d", msg.Type, msg.Data, len(s.messageCh))
		originID := ""
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
			if block, ok := msg.Data.(*types.Block); ok {
				// Validate the block first
				if err := block.Validate(); err != nil {
					log.Printf("Block validation failed: %v", err)
					if originID != "" {
						s.peerManager.UpdatePeerScore(originID, -10)
					}
					continue
				}

				// Add transactions from the block
				for _, tx := range block.Body.TxsList {
					if err := s.blockchain.AddTransaction(tx); err != nil {
						log.Printf("Failed to add block transaction %s: %v", tx.ID, err)
						if originID != "" {
							s.peerManager.UpdatePeerScore(originID, -5)
						}
						continue
					}
				}

				// Commit the block using the new method
				if err := s.blockchain.CommitBlock(block); err != nil {
					log.Printf("Failed to commit block: %v", err)
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
		case "proposal": // New case for consensus proposals
			if proposal, ok := msg.Data.(*consensus.Proposal); ok {
				// Handle consensus proposal - check if consensus is initialized
				if s.consensus != nil {
					if err := s.consensus.HandleProposal(proposal); err != nil {
						log.Printf("Failed to handle consensus proposal: %v", err)
					}
				} else {
					log.Printf("Consensus not initialized, ignoring proposal")
				}
			}
		case "vote": // New case for consensus votes
			if vote, ok := msg.Data.(*consensus.Vote); ok {
				// Handle consensus vote - check if consensus is initialized
				if s.consensus != nil {
					if err := s.consensus.HandleVote(vote); err != nil {
						log.Printf("Failed to handle consensus vote: %v", err)
					}
				} else {
					log.Printf("Consensus not initialized, ignoring vote")
				}
			}
		case "ping":
			if pingData, ok := msg.Data.(network.PingData); ok {
				if peer := s.nodeManager.GetNodeByKademliaID(pingData.FromID); peer != nil {
					if p, ok := s.nodeManager.GetPeers()[peer.ID]; ok {
						p.ReceivePong()
						transport.SendMessage(peer.Address, &security.Message{Type: "pong", Data: network.PongData{
							FromID:    s.localNode.KademliaID,
							ToID:      pingData.FromID,
							Timestamp: time.Now(),
							Nonce:     pingData.Nonce,
						}})
						s.peerManager.UpdatePeerScore(peer.ID, 2)
					}
				}
			} else {
				log.Printf("Invalid ping data")
			}
		case "pong":
			if pongData, ok := msg.Data.(network.PongData); ok {
				if peer := s.nodeManager.GetNodeByKademliaID(pongData.FromID); peer != nil {
					if p, ok := s.nodeManager.GetPeers()[peer.ID]; ok {
						p.ReceivePong()
						s.peerManager.UpdatePeerScore(peer.ID, 2)
					}
				}
			} else {
				log.Printf("Invalid pong data")
			}
		case "peer_info":
			if peerInfo, ok := msg.Data.(network.PeerInfo); ok {
				// FIX: Add the database parameter (use nil or the actual database instance)
				node := network.NewNode(peerInfo.Address, peerInfo.IP, peerInfo.Port, peerInfo.UDPPort, false, peerInfo.Role, nil)
				node.KademliaID = peerInfo.KademliaID
				node.UpdateStatus(peerInfo.Status)
				s.nodeManager.AddNode(node)
				if len(s.peerManager.peers) < s.peerManager.maxPeers {
					s.peerManager.ConnectPeer(node)
				}
				log.Printf("Received PeerInfo: NodeID=%s, Address=%s, Role=%s", peerInfo.NodeID, peerInfo.Address, peerInfo.Role)
			}
		case "version":
			if versionData, ok := msg.Data.(map[string]interface{}); ok {
				peerID, ok := versionData["node_id"].(string)
				if !ok {
					log.Printf("Invalid node_id in version message")
					continue
				}
				node := s.nodeManager.GetNode(peerID)
				if node == nil {
					node = &network.Node{
						ID:         peerID,
						Address:    "",
						Status:     network.NodeStatusActive,
						LastSeen:   time.Now(),
						KademliaID: network.GenerateKademliaID(peerID),
					}
					s.nodeManager.AddNode(node)
					log.Printf("Created temporary node for version message: ID=%s", peerID)
				}
				verackMsg := &security.Message{
					Type: "verack",
					Data: s.localNode.ID,
				}
				sourceAddr := node.Address
				if sourceAddr == "" {
					if addr, ok := versionData["address"].(string); ok && addr != "" {
						sourceAddr = addr
					} else {
						log.Printf("No valid source address for verack to %s", peerID)
						continue
					}
				}
				if err := transport.SendMessage(sourceAddr, verackMsg); err != nil {
					log.Printf("Failed to send verack to %s at %s: %v", peerID, sourceAddr, err)
					s.peerManager.UpdatePeerScore(peerID, -10)
					continue
				}
				log.Printf("Sent verack to %s at %s", peerID, sourceAddr)
				s.peerManager.UpdatePeerScore(peerID, 5)
				if addr, ok := versionData["address"].(string); ok && addr != "" && node.Address == "" {
					node.Address = addr
					if err := s.nodeManager.UpdateNode(node); err != nil {
						log.Printf("Failed to update node %s address to %s: %v", peerID, addr, err)
					} else {
						log.Printf("Updated node %s address to %s", peerID, addr)
					}
				}
			} else {
				log.Printf("Invalid version message data: %v", msg.Data)
			}
		case "getheaders":
			if data, ok := msg.Data.(map[string]interface{}); ok {
				startHeight, ok := data["start_height"].(float64)
				if !ok {
					log.Printf("Invalid start_height in getheaders")
					continue
				}
				blocks := s.blockchain.GetBlocks()
				var headers []*types.BlockHeader // Change to slice of pointers
				for _, block := range blocks {
					if block.Header.Block >= uint64(startHeight) {
						headers = append(headers, block.Header) // Now this works
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

// InitializeConsensus initializes the consensus module for this server
func (s *Server) InitializeConsensus(consensus *consensus.Consensus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.consensus = consensus
	log.Printf("Consensus module initialized for node %s", s.localNode.ID)
}

// GetConsensus returns the consensus instance (if initialized)
func (s *Server) GetConsensus() *consensus.Consensus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.consensus
}

// assignTransactionRoles assigns Sender and Receiver roles based on transaction.
func (s *Server) assignTransactionRoles(tx *types.Transaction) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, node := range s.nodeManager.GetPeers() {
		switch node.Node.Address {
		case tx.Sender:
			node.Node.UpdateRole(network.RoleSender)
		case tx.Receiver:
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
