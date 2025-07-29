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
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/sphinx-core/go/src/core/hashtree"
	sigproof "github.com/sphinx-core/go/src/core/proof"
	key "github.com/sphinx-core/go/src/core/sphincs/key/backend"
	"github.com/sphinx-core/go/src/network"
)

// DiscoverPeers initiates Kademlia-based peer discovery.
func (s *Server) DiscoverPeers() error {
	log.Printf("DiscoverPeers: Starting peer discovery for node %s with %d seed nodes: %v", s.localNode.Address, len(s.seedNodes), s.seedNodes)
	if len(s.seedNodes) == 0 {
		log.Printf("DiscoverPeers: No seed nodes provided for node %s, skipping peer discovery", s.localNode.Address)
		return nil
	}

	receivedPeers := make(map[string]bool)
	timeout := time.After(90 * time.Second)
	seedTimeout := 45 * time.Second
	maxRetries := 3

	for _, seed := range s.seedNodes {
		for retry := 1; retry <= maxRetries; retry++ {
			log.Printf("DiscoverPeers: Processing seed node %s (attempt %d/%d) for %s", seed, retry, maxRetries, s.localNode.Address)
			addr, err := net.ResolveUDPAddr("udp", seed)
			if err != nil {
				log.Printf("DiscoverPeers: Failed to resolve seed address %s for %s: %v", seed, s.localNode.Address, err)
				continue
			}

			configs, err := network.GetNodePortConfigs(3, []network.NodeRole{network.RoleNone, network.RoleNone, network.RoleNone}, nil)
			if err != nil {
				log.Printf("DiscoverPeers: Failed to get node port configs for %s: %v", s.localNode.Address, err)
				continue
			}
			tcpAddr, tcpPort := "", ""
			for _, cfg := range configs {
				if cfg.UDPPort == seed {
					tcpAddr = cfg.TCPAddr
					if len(strings.Split(tcpAddr, ":")) == 2 {
						tcpPort = strings.Split(tcpAddr, ":")[1]
					}
					break
				}
			}
			if tcpAddr == "" {
				parts := strings.Split(seed, ":")
				if len(parts) != 2 {
					log.Printf("DiscoverPeers: Invalid seed address format %s for %s", seed, s.localNode.Address)
					continue
				}
				udpPort, err := strconv.Atoi(parts[1])
				if err != nil {
					log.Printf("DiscoverPeers: Invalid UDP port in %s for %s: %v", seed, s.localNode.Address, err)
					continue
				}
				tcpPort = fmt.Sprintf("%d", udpPort-1)
				tcpAddr = fmt.Sprintf("%s:%s", parts[0], tcpPort)
				log.Printf("DiscoverPeers: Using fallback TCP address %s for seed %s for %s", tcpAddr, seed, s.localNode.Address)
			}

			node := network.NewNode(tcpAddr, addr.IP.String(), tcpPort, seed, false, network.RoleNone)
			if node == nil {
				log.Printf("DiscoverPeers: Failed to create node for seed %s for %s", seed, s.localNode.Address)
				continue
			}
			node.KademliaID = network.GenerateKademliaID(tcpAddr)
			log.Printf("DiscoverPeers: Sending PING to seed node %s (KademliaID: %x) for %s", seed, node.KademliaID[:8], s.localNode.Address)

			nonce := make([]byte, 8)
			_, err = rand.Read(nonce)
			if err != nil {
				log.Printf("DiscoverPeers: Failed to generate nonce for %s for %s: %v", seed, s.localNode.Address, err)
				continue
			}
			s.sendUDPPing(addr, node.KademliaID, nonce)

			seedTimer := time.NewTimer(seedTimeout)
			select {
			case peers := <-s.nodeManager.ResponseCh:
				log.Printf("DiscoverPeers: Received %d peers from %s for %s", len(peers), seed, s.localNode.Address)
				seedTimer.Stop()
				for _, peer := range peers {
					if receivedPeers[peer.Node.ID] {
						log.Printf("DiscoverPeers: Skipping already processed peer %s for %s", peer.Node.Address, s.localNode.Address)
						continue
					}
					receivedPeers[peer.Node.ID] = true
					log.Printf("DiscoverPeers: Processing peer %s (KademliaID: %x) for %s", peer.Node.Address, peer.Node.KademliaID[:8], s.localNode.Address)
					if peer.Node.Address != s.localNode.Address && peer.Node.Address != "" {
						if err := s.peerManager.ConnectPeer(peer.Node); err != nil {
							log.Printf("DiscoverPeers: Failed to connect to peer %s for %s: %v", peer.Node.Address, s.localNode.Address, err)
							continue
						}
						log.Printf("DiscoverPeers: Successfully connected to peer %s for %s", peer.Node.Address, s.localNode.Address)
						go s.iterativeFindNode(peer.Node.KademliaID)
					} else {
						log.Printf("DiscoverPeers: Skipping peer %s (empty address or self) for %s", peer.Node.Address, s.localNode.Address)
					}
				}
				goto ProcessNextSeed
			case <-seedTimer.C:
				log.Printf("DiscoverPeers: Timeout waiting for response from seed %s (attempt %d/%d) for %s", seed, retry, maxRetries, s.localNode.Address)
				if retry == maxRetries {
					log.Printf("DiscoverPeers: All retries exhausted for seed %s for %s", seed, s.localNode.Address)
				}
			case <-timeout:
				log.Printf("DiscoverPeers: Global timeout reached for node %s", s.localNode.Address)
				s.nodeManager.Lock()
				if len(s.nodeManager.GetPeers()) > 0 {
					log.Printf("DiscoverPeers: Found %d peers in nodeManager.GetPeers() for %s despite timeout", len(s.nodeManager.GetPeers()), s.localNode.Address)
					for _, peer := range s.nodeManager.GetPeers() {
						receivedPeers[peer.Node.ID] = true
					}
					s.nodeManager.Unlock()
					return nil
				}
				s.nodeManager.Unlock()
				return errors.New("global timeout reached with no peers found")
			}
			seedTimer.Stop()
			time.Sleep(5 * time.Second)
		}
	ProcessNextSeed:
	}

	if len(receivedPeers) == 0 {
		s.nodeManager.Lock()
		if len(s.nodeManager.GetPeers()) > 0 {
			log.Printf("DiscoverPeers: Found %d peers in nodeManager.GetPeers() for %s", len(s.nodeManager.GetPeers()), s.localNode.Address)
			for _, peer := range s.nodeManager.GetPeers() {
				receivedPeers[peer.Node.ID] = true
			}
			s.nodeManager.Unlock()
			return nil
		}
		s.nodeManager.Unlock()
		log.Printf("DiscoverPeers: No peers found after processing all seed nodes for %s", s.localNode.Address)
		return errors.New("no peers found")
	}
	log.Printf("DiscoverPeers: Found %d peers for %s", len(receivedPeers), s.localNode.Address)
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
					nonce := make([]byte, 32)
					_, err := rand.Read(nonce)
					if err != nil {
						errorCh <- err
						return
					}
					km, err := key.NewKeyManager()
					if err != nil {
						errorCh <- err
						return
					}
					privateKey, _, err := km.DeserializeKeyPair(s.localNode.PrivateKey, s.localNode.PublicKey)
					if err != nil {
						log.Printf("iterativeFindNode: Failed to deserialize key pair: %v", err)
						errorCh <- fmt.Errorf("failed to deserialize key pair: %v", err)
						return
					}
					data := network.FindNodeData{
						TargetID:  targetID,
						Timestamp: time.Now(),
						Nonce:     nonce,
					}
					dataBytes, err := json.Marshal(data)
					if err != nil {
						errorCh <- err
						return
					}
					timestamp := make([]byte, 8)
					binary.BigEndian.PutUint64(timestamp, uint64(data.Timestamp.Unix()))
					signature, merkleRoot, _, _, err := s.sphincsMgr.SignMessage(dataBytes, privateKey)
					if err != nil {
						errorCh <- err
						return
					}
					// Store signature locally
					signatureBytes, err := s.sphincsMgr.SerializeSignature(signature)
					if err != nil {
						errorCh <- err
						return
					}
					err = hashtree.SaveLeavesToDB(s.db, [][]byte{dataBytes, signatureBytes})
					if err != nil {
						log.Printf("iterativeFindNode: Failed to store signature: %v", err)
						errorCh <- err
						return
					}
					proofData := append(timestamp, append(nonce, dataBytes...)...)
					proof, err := sigproof.GenerateSigProof([][]byte{proofData}, [][]byte{merkleRoot.Hash.Bytes()}, s.localNode.PublicKey)
					if err != nil {
						errorCh <- err
						return
					}
					msg := network.DiscoveryMessage{
						Type:       "FINDNODE",
						Data:       dataBytes,
						PublicKey:  s.localNode.PublicKey,
						MerkleRoot: merkleRoot.Hash, // Use *uint256.Int directly
						Proof:      proof,
						Nonce:      nonce,
						Timestamp:  timestamp,
					}
					s.sendUDPMessage(addr, msg)
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
						// Attempt to connect to newly discovered peers
						if p.Node.Address != s.localNode.Address {
							if err := s.peerManager.ConnectPeer(p.Node); err != nil {
								log.Printf("iterativeFindNode: Failed to connect to peer %s: %v", p.Node.Address, err)
								continue
							}
							log.Printf("iterativeFindNode: Successfully connected to peer %s", p.Node.Address)
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
