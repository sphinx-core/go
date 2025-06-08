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

package p2p

import (
	"log"
	"sync"

	"github.com/sphinx-core/go/src/core"
	types "github.com/sphinx-core/go/src/core/transaction"
	"github.com/sphinx-core/go/src/security"
	"github.com/sphinx-core/go/src/transport"
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
func NewServer(address string, seedNodes []string, blockchain *core.Blockchain) *Server {
	return &Server{
		address:    address,
		seedNodes:  seedNodes,
		peers:      make(map[string]*Peer),
		messageCh:  make(chan *security.Message),
		blockchain: blockchain,
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
			if tx, ok := msg.Data.(*types.Transaction); ok {
				if err := s.blockchain.AddTransaction(tx); err != nil {
					log.Printf("Failed to add transaction: %v", err)
				}
			}
		case "block":
			if block, ok := msg.Data.(types.Block); ok {
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
