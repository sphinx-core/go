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

// go/src/p2p/discovery.go
package p2p

import (
	"log"
	"strings"

	"github.com/sphinx-core/go/src/network"
	"github.com/sphinx-core/go/src/security"
	"github.com/sphinx-core/go/src/transport"
)

// DiscoverPeers connects to seed nodes and discovers peers.
func (s *Server) DiscoverPeers() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, seedAddr := range s.seedNodes {
		log.Printf("Attempting to connect to seed node %s", seedAddr)

		if seedAddr == s.localNode.Address {
			log.Printf("Skipping self-address %s", seedAddr)
			continue
		}
		if _, exists := s.nodeManager.GetPeers()[seedAddr]; exists {
			log.Printf("Seed %s already known as peer", seedAddr)
			continue
		}

		parts := strings.Split(seedAddr, ":")
		if len(parts) != 2 {
			log.Printf("Invalid seed address: %s", seedAddr)
			continue
		}
		ip, port := parts[0], parts[1]
		node := network.NewNode(seedAddr, ip, port, false, network.RoleNone)

		if err := transport.ConnectNode(node, s.messageCh); err != nil {
			log.Printf("Failed to connect to seed %s: %v", seedAddr, err)
			continue
		}

		if err := s.nodeManager.AddPeer(node); err != nil {
			log.Printf("Failed to add peer %s (Role=%s): %v", node.ID, node.Role, err)
			continue
		}

		peer := s.nodeManager.GetPeers()[node.ID]
		peer.SendPing()
		s.Broadcast(&security.Message{Type: "ping", Data: s.localNode.ID})
		s.nodeManager.BroadcastPeerInfo(peer, transport.SendPeerInfo)

		log.Printf("Connected to seed node %s as peer: ID=%s, Role=%s", seedAddr, node.ID, node.Role)
	}
	return nil
}
