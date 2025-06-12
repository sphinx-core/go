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
	"net"
	"strings"

	"github.com/sphinx-core/go/src/network"
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
		if net.ParseIP(ip) == nil {
			log.Printf("Invalid IP address: %s", ip)
			continue
		}
		if _, err := net.LookupPort("tcp", port); err != nil {
			log.Printf("Invalid port: %s", port)
			continue
		}

		node := network.NewNode(seedAddr, ip, port, false, network.RoleNone)
		if err := s.peerManager.ConnectPeer(node); err != nil {
			log.Printf("Failed to connect to seed %s: %v", seedAddr, err)
			continue
		}

		log.Printf("Connected to seed node %s as peer: ID=%s, Role=%s", seedAddr, node.ID, node.Role)
	}
	return nil
}
