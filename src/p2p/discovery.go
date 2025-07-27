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
	"time"

	sigproof "github.com/sphinx-core/go/src/core/proof"
	key "github.com/sphinx-core/go/src/core/sphincs/key/backend"
	"github.com/sphinx-core/go/src/network"
)

// DiscoverPeers initiates Kademlia-based peer discovery.
func (s *Server) DiscoverPeers() error {
	log.Printf("DiscoverPeers: Starting peer discovery for node %s with %d seed nodes", s.localNode.Address, len(s.seedNodes))
	if len(s.seedNodes) == 0 {
		log.Printf("DiscoverPeers: No seed nodes provided for node %s", s.localNode.Address)
		return errors.New("no seed nodes provided")
	}

	for _, seed := range s.seedNodes {
		log.Printf("DiscoverPeers: Processing seed node %s", seed)
		addr, err := net.ResolveUDPAddr("udp", seed)
		if err != nil {
			log.Printf("DiscoverPeers: Failed to resolve seed address %s: %v", seed, err)
			continue
		}
		node := network.NewNode(seed, addr.IP.String(), fmt.Sprintf("%d", addr.Port), seed, false, network.RoleNone)
		node.KademliaID = network.GenerateKademliaID(seed)
		log.Printf("DiscoverPeers: Sending PING to seed node %s (KademliaID: %x)", seed, node.KademliaID[:8])

		// Send PING to seed node using sendUDPPing
		nonce := make([]byte, 8)
		_, err = rand.Read(nonce)
		if err != nil {
			log.Printf("DiscoverPeers: Failed to generate nonce for %s: %v", seed, err)
			continue
		}
		s.sendUDPPing(addr, node.KademliaID, nonce)

		// Wait for PONG or NEIGHBORS response
		timeout := time.After(5 * time.Second)
		select {
		case peers := <-s.nodeManager.ResponseCh:
			log.Printf("DiscoverPeers: Received %d peers from %s", len(peers), seed)
			for _, peer := range peers {
				log.Printf("DiscoverPeers: Attempting to connect to peer %s (KademliaID: %x)", peer.Node.Address, peer.Node.KademliaID[:8])
				if peer.Node.Address != s.localNode.Address {
					if err := s.peerManager.ConnectPeer(peer.Node); err != nil {
						log.Printf("DiscoverPeers: Failed to connect to peer %s: %v", peer.Node.Address, err)
						continue
					}
					log.Printf("DiscoverPeers: Successfully connected to peer %s", peer.Node.Address)
					// Perform FINDNODE to discover more peers
					go s.iterativeFindNode(peer.Node.KademliaID)
				}
			}
		case <-timeout:
			log.Printf("DiscoverPeers: Timeout waiting for response from seed %s", seed)
			continue
		}
	}

	if len(s.peerManager.peers) == 0 {
		log.Printf("DiscoverPeers: No peers found after processing all seed nodes")
		return errors.New("no peers found")
	}
	log.Printf("DiscoverPeers: Found %d peers", len(s.peerManager.peers))
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
					signature, merkleRoot, _, nonce, err := s.sphincsMgr.SignMessage(dataBytes, privateKey)
					if err != nil {
						errorCh <- err
						return
					}
					signatureBytes, err := s.sphincsMgr.SerializeSignature(signature)
					if err != nil {
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
						Signature:  signatureBytes,
						PublicKey:  s.localNode.PublicKey,
						MerkleRoot: merkleRoot.Hash.Bytes(),
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
