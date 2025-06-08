// p2p/p2p.go
package p2p

import (
	"log"
	"sync"

	"github.com/yourusername/myblockchain/core"
	"github.com/yourusername/myblockchain/security"
	"github.com/yourusername/myblockchain/transport"
)

// Server manages the P2P network.
type Server struct {
	address    string
	seedNodes  []string
	peers      map[string]*Peer
	mu         sync.Mutex
	messageCh  chan *security.Message
	blockchain *core.Blockchain
}

// NewServer creates a new P2P server.
func NewServer(address string, seedNodes []string) *Server {
	return &Server{
		address:    address,
		seedNodes:  seedNodes,
		peers:      make(map[string]*Peer),
		messageCh:  make(chan *security.Message),
		blockchain: core.NewBlockchain(),
	}
}

// Start initializes the P2P network.
func (s *Server) Start() error {
	go s.handleMessages()
	log.Printf("P2P server started, active chain height: %d", s.blockchain.GetBlockCount())
	return s.DiscoverPeers()
}

// handleMessages processes incoming messages.
func (s *Server) handleMessages() {
	for msg := range s.messageCh {
		log.Printf("Received message: Type=%s, Data=%v", msg.Type, msg.Data)
		switch msg.Type {
		case "transaction":
			if tx, ok := msg.Data.(core.Transaction); ok {
				if err := s.blockchain.AddTransaction(tx); err != nil {
					log.Printf("Failed to add transaction: %v", err)
				}
			}
		case "block":
			if block, ok := msg.Data.(core.Block); ok {
				if err := s.blockchain.AddBlock(); err != nil {
					log.Printf("Failed to add block: %v", err)
				}
				s.Broadcast(&security.Message{Type: "block", Data: block})
			}
		}
		s.Broadcast(msg)
	}
}

// Broadcast sends a message to all peers.
func (s *Server) Broadcast(msg *security.Message) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, peer := range s.peers {
		if err := transport.SendMessage(peer.Address, msg); err != nil {
			log.Printf("Failed to send to %s: %v", peer.Address, err)
		}
	}
}
