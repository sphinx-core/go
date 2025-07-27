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
package p2p

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/holiman/uint256"
	"github.com/sphinx-core/go/src/common"
	"github.com/sphinx-core/go/src/core/hashtree"
	sigproof "github.com/sphinx-core/go/src/core/proof"
	key "github.com/sphinx-core/go/src/core/sphincs/key/backend"
	"github.com/sphinx-core/go/src/network"
)

// toUint256 converts a []byte to *uint256.Int using common.SpxHash, as per hashtree.computeUint256.
func toUint256(data []byte) *uint256.Int {
	hash := common.SpxHash(data) // Use SpxHash from common
	return uint256.NewInt(0).SetBytes(hash)
}

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

	// Deserialize public key and signature
	km, err := key.NewKeyManager()
	if err != nil {
		log.Printf("Failed to initialize KeyManager: %v", err)
		return
	}
	_, publicKey, err := km.DeserializeKeyPair(nil, msg.PublicKey)
	if err != nil {
		log.Printf("Failed to deserialize public key: %v", err)
		return
	}
	signature, err := s.sphincsMgr.DeserializeSignature(msg.Signature)
	if err != nil {
		log.Printf("Failed to deserialize signature: %v", err)
		return
	}

	// Convert MerkleRoot []byte to HashTreeNode for VerifySignature
	merkleRootNode := &hashtree.HashTreeNode{Hash: toUint256(msg.MerkleRoot)}

	// Verify signature
	dataBytes, err := json.Marshal(msg.Data)
	if err != nil {
		log.Printf("Failed to marshal message data: %v", err)
		return
	}
	isValidSig := s.sphincsMgr.VerifySignature(dataBytes, msg.Timestamp, msg.Nonce, signature, publicKey, merkleRootNode)
	if !isValidSig {
		log.Printf("Invalid signature for %s message from %s", msg.Type, addr.String())
		return
	}

	// Verify proof
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

	switch msg.Type {
	case "PING":
		var pingData network.PingData
		if err := json.Unmarshal(dataBytes, &pingData); err != nil {
			log.Printf("Invalid PING data from %s: %v", addr.String(), err)
			return
		}
		log.Printf("Received PING from %s (KademliaID: %x)", addr.String(), pingData.FromID[:8])
		// Create or update node
		node := s.nodeManager.GetNodeByKademliaID(pingData.FromID)
		if node == nil {
			node = network.NewNode("", addr.IP.String(), "", addr.String(), false, network.RoleNone)
			node.KademliaID = pingData.FromID
			node.PublicKey = msg.PublicKey
			s.nodeManager.AddNode(node)
		}
		// Set TCP address based on seed nodes
		for _, seed := range s.seedNodes {
			if seed == addr.String() {
				tcpAddr := s.localNode.Address // Use local node's TCP address for seed
				node.Address = tcpAddr
				break
			}
		}
		node.UpdateStatus(network.NodeStatusActive)
		s.sendUDPPong(addr, pingData.FromID, pingData.Nonce)
	case "PONG":
		var pongData network.PongData
		if err := json.Unmarshal(dataBytes, &pongData); err != nil {
			log.Printf("Invalid PONG data from %s: %v", addr.String(), err)
			return
		}
		log.Printf("Received PONG from %s (KademliaID: %x)", addr.String(), pongData.FromID[:8])
		node := s.nodeManager.GetNodeByKademliaID(pongData.FromID)
		if node == nil {
			node = network.NewNode("", addr.IP.String(), "", addr.String(), false, network.RoleNone)
			node.KademliaID = pongData.FromID
			node.PublicKey = msg.PublicKey
			s.nodeManager.AddNode(node)
		}
		// Set TCP address based on seed nodes
		for _, seed := range s.seedNodes {
			if seed == addr.String() {
				tcpAddr := s.localNode.Address // Use local node's TCP address for seed
				node.Address = tcpAddr
				break
			}
		}
		node.UpdateStatus(network.NodeStatusActive)
		peer := network.NewPeer(node)
		peer.ReceivePong()
		s.nodeManager.ResponseCh <- []*network.Peer{peer}
	case "FINDNODE":
		var findNodeData network.FindNodeData
		if err := json.Unmarshal(dataBytes, &findNodeData); err != nil {
			log.Printf("Invalid FINDNODE data from %s: %v", addr.String(), err)
			return
		}
		log.Printf("Received FINDNODE from %s for target %x", addr.String(), findNodeData.TargetID[:8])
		s.sendUDPNeighbors(addr, findNodeData.TargetID, findNodeData.Nonce)
	case "NEIGHBORS":
		var neighborsData network.NeighborsData
		if err := json.Unmarshal(dataBytes, &neighborsData); err != nil {
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
			peers = append(peers, network.NewPeer(node))
		}
		s.nodeManager.ResponseCh <- peers
	}
}

// sendUDPPing sends a PING message to a node.
func (s *Server) sendUDPPing(addr *net.UDPAddr, toID network.NodeID, nonce []byte) {
	km, err := key.NewKeyManager()
	if err != nil {
		log.Printf("Failed to initialize KeyManager: %v", err)
		return
	}
	privateKey, _, err := km.DeserializeKeyPair(s.localNode.PrivateKey, nil)
	if err != nil {
		log.Printf("Failed to deserialize private key: %v", err)
		return
	}
	data := network.PingData{
		FromID:    s.localNode.KademliaID,
		ToID:      toID,
		Timestamp: time.Now(),
		Nonce:     nonce,
	}
	dataBytes, err := json.Marshal(data)
	if err != nil {
		log.Printf("Failed to marshal PING data: %v", err)
		return
	}
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(data.Timestamp.Unix()))
	signature, merkleRootNode, _, nonce, err := s.sphincsMgr.SignMessage(dataBytes, privateKey)
	if err != nil {
		log.Printf("Failed to sign PING message: %v", err)
		return
	}
	signatureBytes, err := s.sphincsMgr.SerializeSignature(signature)
	if err != nil {
		log.Printf("Failed to serialize signature: %v", err)
		return
	}
	proofData := append(timestamp, append(nonce, dataBytes...)...)
	proof, err := sigproof.GenerateSigProof([][]byte{proofData}, [][]byte{merkleRootNode.Hash.Bytes()}, s.localNode.PublicKey)
	if err != nil {
		log.Printf("Failed to generate proof for PING: %v", err)
		return
	}
	msg := network.DiscoveryMessage{
		Type:       "PING",
		Data:       dataBytes, // Use serialized data
		Signature:  signatureBytes,
		PublicKey:  s.localNode.PublicKey,
		MerkleRoot: merkleRootNode.Hash.Bytes(),
		Proof:      proof,
		Nonce:      nonce,
		Timestamp:  timestamp,
	}
	s.sendUDPMessage(addr, msg)
}

// sendUDPPong sends a PONG message in response to a PING.
func (s *Server) sendUDPPong(addr *net.UDPAddr, toID network.NodeID, nonce []byte) {
	km, err := key.NewKeyManager()
	if err != nil {
		log.Printf("Failed to initialize KeyManager: %v", err)
		return
	}
	privateKey, _, err := km.DeserializeKeyPair(s.localNode.PrivateKey, nil)
	if err != nil {
		log.Printf("Failed to deserialize private key: %v", err)
		return
	}
	data := network.PongData{
		FromID:    s.localNode.KademliaID,
		ToID:      toID,
		Timestamp: time.Now(),
		Nonce:     nonce,
	}
	dataBytes, err := json.Marshal(data)
	if err != nil {
		log.Printf("Failed to marshal PONG data: %v", err)
		return
	}
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(data.Timestamp.Unix()))
	signature, merkleRootNode, _, nonce, err := s.sphincsMgr.SignMessage(dataBytes, privateKey)
	if err != nil {
		log.Printf("Failed to sign PONG message: %v", err)
		return
	}
	signatureBytes, err := s.sphincsMgr.SerializeSignature(signature)
	if err != nil {
		log.Printf("Failed to serialize signature: %v", err)
		return
	}
	proofData := append(timestamp, append(nonce, dataBytes...)...)
	proof, err := sigproof.GenerateSigProof([][]byte{proofData}, [][]byte{merkleRootNode.Hash.Bytes()}, s.localNode.PublicKey)
	if err != nil {
		log.Printf("Failed to generate proof for PONG: %v", err)
		return
	}
	msg := network.DiscoveryMessage{
		Type:       "PONG",
		Data:       dataBytes, // Use serialized data
		Signature:  signatureBytes,
		PublicKey:  s.localNode.PublicKey,
		MerkleRoot: merkleRootNode.Hash.Bytes(),
		Proof:      proof,
		Nonce:      nonce,
		Timestamp:  timestamp,
	}
	s.sendUDPMessage(addr, msg)
}

// sendUDPNeighbors sends a NEIGHBORS message with closest peers.
func (s *Server) sendUDPNeighbors(addr *net.UDPAddr, targetID network.NodeID, nonce []byte) {
	km, err := key.NewKeyManager()
	if err != nil {
		log.Printf("Failed to initialize KeyManager: %v", err)
		return
	}
	privateKey, _, err := km.DeserializeKeyPair(s.localNode.PrivateKey, nil)
	if err != nil {
		log.Printf("Failed to deserialize private key: %v", err)
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
		Nonce:     nonce,
	}
	dataBytes, err := json.Marshal(data)
	if err != nil {
		log.Printf("Failed to marshal NEIGHBORS data: %v", err)
		return
	}
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(data.Timestamp.Unix()))
	signature, merkleRootNode, _, nonce, err := s.sphincsMgr.SignMessage(dataBytes, privateKey)
	if err != nil {
		log.Printf("Failed to sign NEIGHBORS message: %v", err)
		return
	}
	signatureBytes, err := s.sphincsMgr.SerializeSignature(signature)
	if err != nil {
		log.Printf("Failed to serialize signature: %v", err)
		return
	}
	proofData := append(timestamp, append(nonce, dataBytes...)...)
	proof, err := sigproof.GenerateSigProof([][]byte{proofData}, [][]byte{merkleRootNode.Hash.Bytes()}, s.localNode.PublicKey)
	if err != nil {
		log.Printf("Failed to generate proof for NEIGHBORS: %v", err)
		return
	}
	msg := network.DiscoveryMessage{
		Type:       "NEIGHBORS",
		Data:       dataBytes, // Use serialized data
		Signature:  signatureBytes,
		PublicKey:  s.localNode.PublicKey,
		MerkleRoot: merkleRootNode.Hash.Bytes(),
		Proof:      proof,
		Nonce:      nonce,
		Timestamp:  timestamp,
	}
	s.sendUDPMessage(addr, msg)
}

// sendUDPMessage sends a discovery message over UDP.
func (s *Server) sendUDPMessage(addr *net.UDPAddr, msg network.DiscoveryMessage) {
	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("Failed to encode UDP message: %v", err)
		return
	}
	_, err = s.udpConn.WriteToUDP(data, addr)
	if err != nil {
		log.Printf("Failed to send UDP message to %s: %v", addr.String(), err)
	}
}

// StoreDiscoveryMessage stores discovery message leaves in the database.
func (s *Server) StoreDiscoveryMessage(msg *network.DiscoveryMessage) error {
	dataBytes, err := json.Marshal(msg.Data)
	if err != nil {
		return fmt.Errorf("failed to marshal discovery message: %v", err)
	}
	return hashtree.SaveLeavesToDB(s.db, [][]byte{dataBytes})
}
