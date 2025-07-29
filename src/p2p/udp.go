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

// go/src/p2p/udp.go
// go/src/p2p/udp.go
package p2p

import (
	"encoding/binary"
	"encoding/json"
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

// StartUDPDiscovery starts the UDP server for peer discovery.
func (s *Server) StartUDPDiscovery(udpPort string) error {
	addr, err := net.ResolveUDPAddr("udp", udpPort)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	s.udpConn = conn
	go s.handleUDP()
	log.Printf("UDP discovery started on %s", udpPort)
	return nil
}

// handleUDP processes incoming UDP messages.
func (s *Server) handleUDP() {
	buffer := make([]byte, 2048)
	for {
		n, addr, err := s.udpConn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("Error reading UDP message: %v", err)
			continue
		}
		var msg network.DiscoveryMessage
		if err := json.Unmarshal(buffer[:n], &msg); err != nil {
			log.Printf("Error decoding UDP message: %v", err)
			continue
		}
		go s.handleDiscoveryMessage(&msg, addr)
	}
}

// handleDiscoveryMessage processes discovery messages (PING, PONG, FINDNODE, NEIGHBORS).
func (s *Server) handleDiscoveryMessage(msg *network.DiscoveryMessage, addr *net.UDPAddr) {
	// Check timestamp freshness (5-minute window)
	timestampInt := binary.BigEndian.Uint64(msg.Timestamp)
	currentTimestamp := uint64(time.Now().Unix())
	if currentTimestamp-timestampInt > 300 {
		log.Printf("Message %s from %s has old timestamp, possible replay", msg.Type, addr.String())
		return
	}

	// Check for signature reuse
	exists, err := s.sphincsMgr.CheckTimestampNonce(msg.Timestamp, msg.Nonce)
	if err != nil {
		log.Printf("Failed to check timestamp-nonce pair: %v", err)
		return
	}
	if exists {
		log.Printf("Signature reuse detected for %s message from %s", msg.Type, addr.String())
		return
	}

	// Validate public key
	if len(msg.PublicKey) == 0 {
		log.Printf("Empty public key in %s message from %s", msg.Type, addr.String())
		return
	}

	// Deserialize public key
	km, err := key.NewKeyManager()
	if err != nil {
		log.Printf("Failed to initialize KeyManager: %v", err)
		return
	}
	if _, err := km.DeserializePublicKey(msg.PublicKey); err != nil {
		log.Printf("Failed to deserialize public key from %s: %v", addr.String(), err)
		return
	}

	// Verify proof
	dataBytes := msg.Data
	proofData := append(msg.Timestamp, append(msg.Nonce, dataBytes...)...)
	regeneratedProof, err := sigproof.GenerateSigProof([][]byte{proofData}, [][]byte{msg.MerkleRoot}, msg.PublicKey)
	if err != nil {
		log.Printf("Failed to regenerate proof for %s message: %v", msg.Type, err)
		return
	}
	isValidProof := sigproof.VerifySigProof(msg.Proof, regeneratedProof)
	if !isValidProof {
		log.Printf("Invalid proof for %s message from %s", msg.Type, addr.String())
		return
	}
	if err := s.StoreDiscoveryMessage(msg); err != nil {
		log.Printf("Failed to store discovery message: %v", err)
	}

	// Store timestamp-nonce pair after verification
	err = s.sphincsMgr.StoreTimestampNonce(msg.Timestamp, msg.Nonce)
	if err != nil {
		log.Printf("Failed to store timestamp-nonce pair: %v", err)
		return
	}

	// Helper function to get TCP address from seed nodes
	getTCPAddress := func(udpAddr string) (string, string) {
		// Check if the UDP address matches any seed node
		configs, _ := network.GetNodePortConfigs(2, []network.NodeRole{network.RoleNone, network.RoleNone}, nil)
		for _, cfg := range configs {
			if cfg.UDPPort == udpAddr {
				if cfg.TCPAddr != "" {
					parts := strings.Split(cfg.TCPAddr, ":")
					if len(parts) == 2 {
						return cfg.TCPAddr, parts[1]
					}
				}
			}
		}
		// Fallback: Assume TCP port is one less than UDP port
		parts := strings.Split(udpAddr, ":")
		if len(parts) != 2 {
			log.Printf("Invalid UDP address format %s", udpAddr)
			return "", ""
		}
		udpPort, err := strconv.Atoi(parts[1])
		if err != nil {
			log.Printf("Invalid UDP port in %s: %v", udpAddr, err)
			return "", ""
		}
		tcpPort := fmt.Sprintf("%d", udpPort-1)
		tcpAddr := fmt.Sprintf("%s:%s", parts[0], tcpPort)
		log.Printf("Using fallback TCP address %s for UDP address %s", tcpAddr, udpAddr)
		return tcpAddr, tcpPort
	}

	switch msg.Type {
	case "PING":
		var pingData network.PingData
		if err := json.Unmarshal(msg.Data, &pingData); err != nil {
			log.Printf("Invalid PING data from %s: %v", addr.String(), err)
			return
		}
		log.Printf("Received PING from %s (KademliaID: %x)", addr.String(), pingData.FromID[:8])
		// Create or update node
		node := s.nodeManager.GetNodeByKademliaID(pingData.FromID)
		tcpAddr, tcpPort := getTCPAddress(addr.String())
		if node == nil {
			node = network.NewNode(tcpAddr, addr.IP.String(), tcpPort, addr.String(), false, network.RoleNone)
			node.KademliaID = pingData.FromID
			node.PublicKey = msg.PublicKey
			s.nodeManager.AddNode(node)
			log.Printf("Added node: ID=%s, Address=%s, Role=%s, KademliaID=%x", node.ID, node.Address, node.Role, node.KademliaID[:8])
		} else {
			// Update existing node with TCP address and port if available
			if tcpAddr != "" {
				node.Address = tcpAddr
				node.Port = tcpPort
			}
			node.IP = addr.IP.String()
			node.UDPPort = addr.String()
			node.PublicKey = msg.PublicKey
			log.Printf("Updated node: ID=%s, Address=%s, Role=%s, KademliaID=%x", node.ID, node.Address, node.Role, node.KademliaID[:8])
		}
		node.UpdateStatus(network.NodeStatusActive)
		s.sendUDPPong(addr, pingData.FromID, pingData.Nonce)
	case "PONG":
		var pongData network.PongData
		if err := json.Unmarshal(msg.Data, &pongData); err != nil {
			log.Printf("Invalid PONG data from %s: %v", addr.String(), err)
			return
		}
		log.Printf("Received PONG from %s (KademliaID: %x)", addr.String(), pongData.FromID[:8])
		tcpAddr, tcpPort := getTCPAddress(addr.String())
		if tcpAddr == "" || tcpPort == "" {
			log.Printf("Skipping node creation for %s: no valid TCP address found", addr.String())
			return
		}
		node := s.nodeManager.GetNodeByKademliaID(pongData.FromID)
		if node == nil {
			node = network.NewNode(tcpAddr, addr.IP.String(), tcpPort, addr.String(), false, network.RoleNone)
			node.KademliaID = pongData.FromID
			node.PublicKey = msg.PublicKey
			s.nodeManager.AddNode(node)
			log.Printf("Added node: ID=%s, Address=%s, Role=%s, KademliaID=%x", node.ID, node.Address, node.Role, node.KademliaID[:8])
		} else {
			if tcpAddr != "" {
				node.Address = tcpAddr
				node.Port = tcpPort
			}
			node.IP = addr.IP.String()
			node.UDPPort = addr.String()
			node.PublicKey = msg.PublicKey
			log.Printf("Updated node: ID=%s, Address=%s, Role=%s, KademliaID=%x", node.ID, node.Address, node.Role, node.KademliaID[:8])
		}
		node.UpdateStatus(network.NodeStatusActive)
		peer := network.NewPeer(node)
		peer.ReceivePong()
		if err := s.nodeManager.AddPeer(node); err != nil {
			log.Printf("Failed to add peer %s to nodeManager.peers: %v", node.ID, err)
		} else {
			log.Printf("Added peer %s to nodeManager.peers", node.ID)
		}
		if node.Address != s.localNode.Address {
			if err := s.peerManager.ConnectPeer(node); err != nil {
				log.Printf("Failed to connect to peer %s via TCP: %v", node.ID, err)
			} else {
				log.Printf("Successfully connected to peer %s via ConnectPeer", node.ID)
			}
		}
		log.Printf("Sending peer %s to ResponseCh (ChannelLen=%d)", node.ID, len(s.nodeManager.ResponseCh))
		s.nodeManager.ResponseCh <- []*network.Peer{peer}
		log.Printf("Sent peer %s to ResponseCh (ChannelLen=%d)", node.ID, len(s.nodeManager.ResponseCh))
	case "FINDNODE":
		var findNodeData network.FindNodeData
		if err := json.Unmarshal(msg.Data, &findNodeData); err != nil {
			log.Printf("Invalid FINDNODE data from %s: %v", addr.String(), err)
			return
		}
		log.Printf("Received FINDNODE from %s for target %x", addr.String(), findNodeData.TargetID[:8])
		s.sendUDPNeighbors(addr, findNodeData.TargetID, findNodeData.Nonce)
	case "NEIGHBORS":
		var neighborsData network.NeighborsData
		if err := json.Unmarshal(msg.Data, &neighborsData); err != nil {
			log.Printf("Invalid NEIGHBORS data from %s: %v", addr.String(), err)
			return
		}
		log.Printf("Received NEIGHBORS from %s with %d peers", addr.String(), len(neighborsData.Nodes))
		peers := make([]*network.Peer, 0, len(neighborsData.Nodes))
		for _, nodeInfo := range neighborsData.Nodes {
			node := network.NewNode(nodeInfo.Address, nodeInfo.IP, nodeInfo.Port, nodeInfo.UDPPort, false, nodeInfo.Role)
			node.KademliaID = nodeInfo.KademliaID
			node.PublicKey = nodeInfo.PublicKey
			node.UpdateStatus(nodeInfo.Status)
			s.nodeManager.AddNode(node)
			log.Printf("Added node from NEIGHBORS: ID=%s, Address=%s, Role=%s, KademliaID=%x", node.ID, node.Address, node.Role, node.KademliaID[:8])
			peers = append(peers, network.NewPeer(node))
		}
		s.nodeManager.ResponseCh <- peers
	}
}

// sendUDPPing sends a PING message to a node.
func (s *Server) sendUDPPing(addr *net.UDPAddr, toID network.NodeID, nonce []byte) {
	km, err := key.NewKeyManager()
	if err != nil {
		log.Printf("sendUDPPing: Failed to initialize KeyManager: %v", err)
		return
	}
	log.Printf("sendUDPPing: Deserializing keys for node %s: PrivateKey length=%d, PublicKey length=%d", s.localNode.Address, len(s.localNode.PrivateKey), len(s.localNode.PublicKey))
	privateKey, _, err := km.DeserializeKeyPair(s.localNode.PrivateKey, s.localNode.PublicKey)
	if err != nil {
		log.Printf("sendUDPPing: Failed to deserialize key pair: %v", err)
		return
	}
	data := network.PingData{
		FromID:    s.localNode.KademliaID,
		ToID:      toID,
		Timestamp: time.Now(),
		Nonce:     nonce, // Use the provided nonce
	}
	dataBytes, err := json.Marshal(data)
	if err != nil {
		log.Printf("sendUDPPing: Failed to marshal PING data: %v", err)
		return
	}
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(data.Timestamp.Unix()))
	signature, merkleRootNode, _, _, err := s.sphincsMgr.SignMessage(dataBytes, privateKey)
	if err != nil {
		log.Printf("sendUDPPing: Failed to sign PING message: %v", err)
		return
	}
	// Store signature locally
	signatureBytes, err := s.sphincsMgr.SerializeSignature(signature)
	if err != nil {
		log.Printf("sendUDPPing: Failed to serialize signature: %v", err)
		return
	}
	err = hashtree.SaveLeavesToDB(s.db, [][]byte{dataBytes, signatureBytes})
	if err != nil {
		log.Printf("sendUDPPing: Failed to store signature: %v", err)
		return
	}
	proofData := append(timestamp, append(nonce, dataBytes...)...) // Use the provided nonce
	proof, err := sigproof.GenerateSigProof([][]byte{proofData}, [][]byte{merkleRootNode.Hash.Bytes()}, s.localNode.PublicKey)
	if err != nil {
		log.Printf("sendUDPPing: Failed to generate proof for PING: %v", err)
		return
	}
	msg := network.DiscoveryMessage{
		Type:       "PING",
		Data:       dataBytes, // Store as []byte
		PublicKey:  s.localNode.PublicKey,
		MerkleRoot: merkleRootNode.Hash.Bytes(),
		Proof:      proof,
		Nonce:      nonce, // Use the provided nonce
		Timestamp:  timestamp,
	}
	s.sendUDPMessage(addr, msg)
	log.Printf("sendUDPPing: Sent PING to %s (KademliaID: %x)", addr.String(), toID[:8])
}

// sendUDPPong sends a PONG message in response to a PING.
func (s *Server) sendUDPPong(addr *net.UDPAddr, toID network.NodeID, nonce []byte) {
	km, err := key.NewKeyManager()
	if err != nil {
		log.Printf("sendUDPPong: Failed to initialize KeyManager: %v", err)
		return
	}
	log.Printf("sendUDPPong: Deserializing keys for node %s: PrivateKey length=%d, PublicKey length=%d", s.localNode.Address, len(s.localNode.PrivateKey), len(s.localNode.PublicKey))
	privateKey, _, err := km.DeserializeKeyPair(s.localNode.PrivateKey, s.localNode.PublicKey)
	if err != nil {
		log.Printf("sendUDPPong: Failed to deserialize key pair: %v", err)
		return
	}
	data := network.PongData{
		FromID:    s.localNode.KademliaID,
		ToID:      toID,
		Timestamp: time.Now(),
		Nonce:     nonce, // Use the provided nonce
	}
	dataBytes, err := json.Marshal(data)
	if err != nil {
		log.Printf("sendUDPPong: Failed to marshal PONG data: %v", err)
		return
	}
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(data.Timestamp.Unix()))
	signature, merkleRootNode, _, _, err := s.sphincsMgr.SignMessage(dataBytes, privateKey)
	if err != nil {
		log.Printf("sendUDPPong: Failed to sign PONG message: %v", err)
		return
	}
	// Store signature locally
	signatureBytes, err := s.sphincsMgr.SerializeSignature(signature)
	if err != nil {
		log.Printf("sendUDPPong: Failed to serialize signature: %v", err)
		return
	}
	err = hashtree.SaveLeavesToDB(s.db, [][]byte{dataBytes, signatureBytes})
	if err != nil {
		log.Printf("sendUDPPong: Failed to store signature: %v", err)
		return
	}
	proofData := append(timestamp, append(nonce, dataBytes...)...) // Use the provided nonce
	proof, err := sigproof.GenerateSigProof([][]byte{proofData}, [][]byte{merkleRootNode.Hash.Bytes()}, s.localNode.PublicKey)
	if err != nil {
		log.Printf("sendUDPPong: Failed to generate proof for PONG: %v", err)
		return
	}
	msg := network.DiscoveryMessage{
		Type:       "PONG",
		Data:       dataBytes, // Store as []byte
		PublicKey:  s.localNode.PublicKey,
		MerkleRoot: merkleRootNode.Hash.Bytes(),
		Proof:      proof,
		Nonce:      nonce, // Use the provided nonce
		Timestamp:  timestamp,
	}
	s.sendUDPMessage(addr, msg)
	log.Printf("sendUDPPong: Sent PONG to %s (KademliaID: %x)", addr.String(), toID[:8])
}

// sendUDPNeighbors sends a NEIGHBORS message with closest peers.
func (s *Server) sendUDPNeighbors(addr *net.UDPAddr, targetID network.NodeID, nonce []byte) {
	km, err := key.NewKeyManager()
	if err != nil {
		log.Printf("sendUDPNeighbors: Failed to initialize KeyManager: %v", err)
		return
	}
	log.Printf("sendUDPNeighbors: Deserializing keys for node %s: PrivateKey length=%d, PublicKey length=%d", s.localNode.Address, len(s.localNode.PrivateKey), len(s.localNode.PublicKey))
	privateKey, _, err := km.DeserializeKeyPair(s.localNode.PrivateKey, s.localNode.PublicKey)
	if err != nil {
		log.Printf("sendUDPNeighbors: Failed to deserialize key pair: %v", err)
		return
	}
	peers := s.nodeManager.FindClosestPeers(targetID, s.nodeManager.K)
	neighbors := make([]network.PeerInfo, 0, len(peers))
	for _, peer := range peers {
		neighbors = append(neighbors, peer.GetPeerInfo())
	}
	data := network.NeighborsData{
		Nodes:     neighbors,
		Timestamp: time.Now(),
		Nonce:     nonce, // Use the provided nonce
	}
	dataBytes, err := json.Marshal(data)
	if err != nil {
		log.Printf("sendUDPNeighbors: Failed to marshal NEIGHBORS data: %v", err)
		return
	}
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(data.Timestamp.Unix()))
	signature, merkleRootNode, _, _, err := s.sphincsMgr.SignMessage(dataBytes, privateKey)
	if err != nil {
		log.Printf("sendUDPNeighbors: Failed to sign NEIGHBORS message: %v", err)
		return
	}
	// Store signature locally
	signatureBytes, err := s.sphincsMgr.SerializeSignature(signature)
	if err != nil {
		log.Printf("sendUDPNeighbors: Failed to serialize signature: %v", err)
		return
	}
	err = hashtree.SaveLeavesToDB(s.db, [][]byte{dataBytes, signatureBytes})
	if err != nil {
		log.Printf("sendUDPNeighbors: Failed to store signature: %v", err)
		return
	}
	proofData := append(timestamp, append(nonce, dataBytes...)...) // Use the provided nonce
	proof, err := sigproof.GenerateSigProof([][]byte{proofData}, [][]byte{merkleRootNode.Hash.Bytes()}, s.localNode.PublicKey)
	if err != nil {
		log.Printf("sendUDPNeighbors: Failed to generate proof for NEIGHBORS: %v", err)
		return
	}
	msg := network.DiscoveryMessage{
		Type:       "NEIGHBORS",
		Data:       dataBytes, // Store as []byte
		PublicKey:  s.localNode.PublicKey,
		MerkleRoot: merkleRootNode.Hash.Bytes(),
		Proof:      proof,
		Nonce:      nonce, // Use the provided nonce
		Timestamp:  timestamp,
	}
	s.sendUDPMessage(addr, msg)
	log.Printf("sendUDPNeighbors: Sent NEIGHBORS to %s with %d peers", addr.String(), len(neighbors))
}

// sendUDPMessage sends a discovery message over UDP.
func (s *Server) sendUDPMessage(addr *net.UDPAddr, msg network.DiscoveryMessage) {
	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("sendUDPMessage: Failed to encode UDP message: %v", err)
		return
	}
	_, err = s.udpConn.WriteToUDP(data, addr)
	if err != nil {
		log.Printf("sendUDPMessage: Failed to send UDP message to %s: %v", addr.String(), err)
	}
}

// StoreDiscoveryMessage stores discovery message leaves in the database.
func (s *Server) StoreDiscoveryMessage(msg *network.DiscoveryMessage) error {
	return hashtree.SaveLeavesToDB(s.db, [][]byte{msg.Data})
}
