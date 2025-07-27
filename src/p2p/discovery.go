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
	"encoding/json"
	"log"
	"net"
	"strings"
	"time"

	key "github.com/sphinx-core/go/src/core/sphincs/key/backend"
	"github.com/sphinx-core/go/src/network"
)

// DiscoverPeers initiates Kademlia-based peer discovery.
func (s *Server) DiscoverPeers() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, seedAddr := range s.seedNodes {
		if seedAddr == s.localNode.UDPPort {
			continue
		}
		parts := strings.Split(seedAddr, ":")
		if len(parts) != 2 {
			log.Printf("Invalid seed address: %s", seedAddr)
			continue
		}
		ip := parts[0]
		if net.ParseIP(ip) == nil {
			log.Printf("Invalid IP address: %s", ip)
			continue
		}
		addr, err := net.ResolveUDPAddr("udp", seedAddr)
		if err != nil {
			log.Printf("Failed to resolve UDP address %s: %v", seedAddr, err)
			continue
		}
		s.sendUDPPing(addr, network.NodeID{})
	}
	go s.iterativeFindNode(s.localNode.KademliaID)
	return nil
}

// iterativeFindNode performs iterative FINDNODE queries with hop tracking and error handling.
func (s *Server) iterativeFindNode(targetID network.NodeID) {
	const maxAttempts = 5
	const queryTimeout = 5 * time.Second
	const maxHops = 20 // Prevent infinite loops

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		hopCount := 0
		visited := make(map[string]bool)
		closestDistance := s.nodeManager.CalculateDistance(s.localNode.KademliaID, targetID)
		closestPeers := s.nodeManager.FindClosestPeers(targetID, s.nodeManager.K)

		for len(closestPeers) > 0 && hopCount < maxHops {
			newClosestDistance := closestDistance
			newClosestPeers := make([]*network.Peer, 0, s.nodeManager.K)
			responseCh := make(chan []*network.Peer, len(closestPeers))
			errorCh := make(chan error, len(closestPeers))

			for _, peer := range closestPeers {
				if visited[peer.Node.ID] {
					continue
				}
				visited[peer.Node.ID] = true
				addr, err := net.ResolveUDPAddr("udp", peer.Node.UDPPort)
				if err != nil {
					log.Printf("Failed to resolve UDP address %s: %v", peer.Node.UDPPort, err)
					continue
				}
				go func(peer *network.Peer, addr *net.UDPAddr) {
					km, err := key.NewKeyManager()
					if err != nil {
						errorCh <- err
						return
					}
					data := network.FindNodeData{TargetID: targetID}
					dataBytes, _ := json.Marshal(data)
					signature, err := km.Sign(s.localNode.PrivateKey, dataBytes)
					if err != nil {
						errorCh <- err
						return
					}
					msg := network.DiscoveryMessage{
						Type:      "FINDNODE",
						Data:      data,
						Signature: signature,
						PublicKey: s.localNode.PublicKey,
					}
					s.sendUDPMessage(addr, msg)
					// Wait for NEIGHBORS response (handled in udp.go)
					select {
					case peers := <-s.nodeManager.ResponseCh:
						responseCh <- peers
					case <-time.After(queryTimeout):
						errorCh <- nil // Timeout, no error
					}
				}(peer, addr)
			}

			// Collect responses with timeout
			for i := 0; i < len(closestPeers); i++ {
				select {
				case peers := <-responseCh:
					for _, p := range peers {
						distance := s.nodeManager.CalculateDistance(p.Node.KademliaID, targetID)
						if s.nodeManager.CompareDistance(distance, newClosestDistance) < 0 {
							newClosestDistance = distance
							newClosestPeers = []*network.Peer{p}
						} else if s.nodeManager.CompareDistance(distance, newClosestDistance) == 0 {
							newClosestPeers = append(newClosestPeers, p)
						}
					}
				case err := <-errorCh:
					if err != nil {
						log.Printf("Error in FINDNODE query: %v", err)
					}
				case <-time.After(queryTimeout):
					log.Printf("Timeout waiting for FINDNODE response")
				}
			}

			if s.nodeManager.CompareDistance(newClosestDistance, closestDistance) >= 0 {
				// No closer peers found
				break
			}
			closestDistance = newClosestDistance
			closestPeers = newClosestPeers
			hopCount++
			log.Printf("FINDNODE hop %d: %d peers queried, closest distance updated", hopCount, len(closestPeers))
		}

		log.Printf("Completed FINDNODE for target %x after %d hops (%d peers visited)", targetID[:8], hopCount, len(visited))
		if hopCount > 0 || len(closestPeers) > 0 {
			// Success or partial success
			return
		}
		log.Printf("No progress in attempt %d, retrying after delay", attempt)
		time.Sleep(10 * time.Second)
	}
	log.Printf("Failed to find peers for target %x after %d attempts", targetID[:8], maxAttempts)
}
