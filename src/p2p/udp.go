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
	// Set a larger read buffer to handle potential large messages
	err = conn.SetReadBuffer(65535) // 64 KB buffer
	if err != nil {
		log.Printf("StartUDPDiscovery: Failed to set read buffer for %s: %v", udpPort, err)
	}
	s.udpConn = conn
	s.stopCh = make(chan struct{})
	go s.handleUDP()
	log.Printf("UDP discovery started on %s", udpPort)
	if s.udpReadyCh != nil {
		s.udpReadyCh <- struct{}{}
	}
	return nil
}

// handleUDP processes incoming UDP messages.
func (s *Server) handleUDP() {
	buffer := make([]byte, 65535) // Increased buffer size to 64 KB
	for {
		select {
		case <-s.stopCh:
			log.Printf("handleUDP: Stopping UDP handler for %s", s.localNode.Address)
			return
		default:
			n, addr, err := s.udpConn.ReadFromUDP(buffer)
			if err != nil {
				if strings.Contains(err.Error(), "use of closed network connection") {
					log.Printf("handleUDP: UDP connection closed for %s", s.localNode.Address)
					return
				}
				log.Printf("handleUDP: Error reading UDP message for %s: %v", s.localNode.Address, err)
				continue
			}
			log.Printf("handleUDP: Received UDP message from %s for %s: %s", addr.String(), s.localNode.Address, string(buffer[:n]))
			var msg network.DiscoveryMessage
			if err := json.Unmarshal(buffer[:n], &msg); err != nil {
				log.Printf("handleUDP: Error decoding UDP message from %s for %s: %v", addr.String(), s.localNode.Address, err)
				continue
			}
			go s.handleDiscoveryMessage(&msg, addr)
		}
	}
}

// handleDiscoveryMessage processes discovery messages (PING, PONG, FINDNODE, NEIGHBORS).
func (s *Server) handleDiscoveryMessage(msg *network.DiscoveryMessage, addr *net.UDPAddr) {
	log.Printf("handleDiscoveryMessage: Received %s message from %s for node %s: Timestamp=%x, Nonce=%x", msg.Type, addr.String(), s.localNode.Address, msg.Timestamp, msg.Nonce[:8])
	// Check timestamp freshness (5-minute window)
	timestampInt := binary.BigEndian.Uint64(msg.Timestamp)
	currentTimestamp := uint64(time.Now().Unix())
	if currentTimestamp-timestampInt > 300 {
		log.Printf("handleDiscoveryMessage: Message %s from %s for %s has old timestamp (%d), possible replay", msg.Type, addr.String(), s.localNode.Address, currentTimestamp-timestampInt)
		return
	}

	// Check for signature reuse
	exists, err := s.sphincsMgr.CheckTimestampNonce(msg.Timestamp, msg.Nonce)
	if err != nil {
		log.Printf("handleDiscoveryMessage: Failed to check timestamp-nonce pair for %s from %s: %v", msg.Type, addr.String(), err)
		return
	}
	if exists {
		log.Printf("handleDiscoveryMessage: Signature reuse detected for %s message from %s for %s", msg.Type, addr.String(), s.localNode.Address)
		return
	}

	// Validate public key
	if len(msg.PublicKey) == 0 {
		log.Printf("handleDiscoveryMessage: Empty public key in %s message from %s for %s", msg.Type, addr.String(), s.localNode.Address)
		return
	}

	// Verify proof
	dataBytes := msg.Data
	proofData := append(msg.Timestamp, append(msg.Nonce, dataBytes...)...)
	regeneratedProof, err := sigproof.GenerateSigProof([][]byte{proofData}, [][]byte{msg.MerkleRoot.Bytes()}, msg.PublicKey)
	if err != nil {
		log.Printf("handleDiscoveryMessage: Failed to regenerate proof for %s message from %s for %s: %v", msg.Type, addr.String(), s.localNode.Address, err)
		return
	}
	isValidProof := sigproof.VerifySigProof(msg.Proof, regeneratedProof)
	if !isValidProof {
		log.Printf("handleDiscoveryMessage: Invalid proof for %s message from %s for %s", msg.Type, addr.String(), s.localNode.Address)
		return
	}

	// Store message data
	if err := s.StoreDiscoveryMessage(msg); err != nil {
		log.Printf("handleDiscoveryMessage: Failed to store discovery message for %s from %s: %v", msg.Type, addr.String(), err)
	}

	// Store timestamp-nonce pair after verification
	err = s.sphincsMgr.StoreTimestampNonce(msg.Timestamp, msg.Nonce)
	if err != nil {
		log.Printf("handleDiscoveryMessage: Failed to store timestamp-nonce pair for %s from %s: %v", msg.Type, addr.String(), err)
		return
	}

	getTCPAddress := func(udpAddr string) (string, string) {
		configs, _ := network.GetNodePortConfigs(3, []network.NodeRole{network.RoleNone, network.RoleNone, network.RoleNone}, nil)
		for _, cfg := range configs {
			if cfg.UDPPort == udpAddr {
				if cfg.TCPAddr != "" {
					parts := strings.Split(cfg.TCPAddr, ":")
					if len(parts) == 2 {
						log.Printf("handleDiscoveryMessage: Found TCP address %s for UDP address %s", cfg.TCPAddr, udpAddr)
						return cfg.TCPAddr, parts[1]
					}
				}
			}
		}
		parts := strings.Split(udpAddr, ":")
		if len(parts) != 2 {
			log.Printf("handleDiscoveryMessage: Invalid UDP address format %s", udpAddr)
			return "", ""
		}
		udpPort, err := strconv.Atoi(parts[1])
		if err != nil {
			log.Printf("handleDiscoveryMessage: Invalid UDP port in %s: %v", udpAddr, err)
			return "", ""
		}
		tcpPort := fmt.Sprintf("%d", udpPort-1)
		tcpAddr := fmt.Sprintf("%s:%s", parts[0], tcpPort)
		log.Printf("handleDiscoveryMessage: Using fallback TCP address %s for UDP address %s", tcpAddr, udpAddr)
		return tcpAddr, tcpPort
	}

	switch msg.Type {
	case "PING":
		var pingData network.PingData
		if err := json.Unmarshal(msg.Data, &pingData); err != nil {
			log.Printf("handleDiscoveryMessage: Invalid PING data from %s for %s: %v", addr.String(), s.localNode.Address, err)
			return
		}
		log.Printf("handleDiscoveryMessage: Received PING from %s (KademliaID: %x) for %s", addr.String(), pingData.FromID[:8], s.localNode.Address)
		node := s.nodeManager.GetNodeByKademliaID(pingData.FromID)
		tcpAddr, tcpPort := getTCPAddress(addr.String())
		if node == nil {
			node = network.NewNode(tcpAddr, addr.IP.String(), tcpPort, addr.String(), false, network.RoleNone)
			node.KademliaID = pingData.FromID
			node.PublicKey = msg.PublicKey
			s.nodeManager.AddNode(node)
			log.Printf("handleDiscoveryMessage: Added node: ID=%s, Address=%s, Role=%s, KademliaID=%x", node.ID, node.Address, node.Role, node.KademliaID[:8])
		} else {
			if tcpAddr != "" {
				node.Address = tcpAddr
				node.Port = tcpPort
			}
			node.IP = addr.IP.String()
			node.UDPPort = addr.String()
			node.PublicKey = msg.PublicKey
			log.Printf("handleDiscoveryMessage: Updated node: ID=%s, Address=%s, Role=%s, KademliaID=%x", node.ID, node.Address, node.Role, node.KademliaID[:8])
		}
		node.UpdateStatus(network.NodeStatusActive)
		s.sendUDPPong(addr, pingData.FromID, pingData.Nonce)
	case "PONG":
		var pongData network.PongData
		if err := json.Unmarshal(msg.Data, &pongData); err != nil {
			log.Printf("handleDiscoveryMessage: Invalid PONG data from %s for %s: %v", addr.String(), s.localNode.Address, err)
			return
		}
		log.Printf("handleDiscoveryMessage: Received PONG from %s (KademliaID: %x) for %s", addr.String(), pongData.FromID[:8], s.localNode.Address)
		tcpAddr, tcpPort := getTCPAddress(addr.String())
		if tcpAddr == "" || tcpPort == "" {
			log.Printf("handleDiscoveryMessage: Skipping node creation for %s: no valid TCP address found", addr.String())
			return
		}
		node := s.nodeManager.GetNodeByKademliaID(pongData.FromID)
		if node == nil {
			node = network.NewNode(tcpAddr, addr.IP.String(), tcpPort, addr.String(), false, network.RoleNone)
			node.KademliaID = pongData.FromID
			node.PublicKey = msg.PublicKey
			s.nodeManager.AddNode(node)
			log.Printf("handleDiscoveryMessage: Added node: ID=%s, Address=%s, Role=%s, KademliaID=%x", node.ID, node.Address, node.Role, node.KademliaID[:8])
		} else {
			if tcpAddr != "" {
				node.Address = tcpAddr
				node.Port = tcpPort
			}
			node.IP = addr.IP.String()
			node.UDPPort = addr.String()
			node.PublicKey = msg.PublicKey
			log.Printf("handleDiscoveryMessage: Updated node: ID=%s, Address=%s, Role=%s, KademliaID=%x", node.ID, node.Address, node.Role, node.KademliaID[:8])
		}
		node.UpdateStatus(network.NodeStatusActive)
		peer := network.NewPeer(node)
		peer.ReceivePong()
		if err := s.nodeManager.AddPeer(node); err != nil {
			log.Printf("handleDiscoveryMessage: Failed to add peer %s to nodeManager.peers for %s: %v", node.ID, s.localNode.Address, err)
		} else {
			log.Printf("handleDiscoveryMessage: Added peer %s to nodeManager.peers for %s", node.ID, s.localNode.Address)
		}
		if node.Address != s.localNode.Address {
			if err := s.peerManager.ConnectPeer(node); err != nil {
				log.Printf("handleDiscoveryMessage: Failed to connect to peer %s via TCP for %s: %v", node.ID, s.localNode.Address, err)
			} else {
				log.Printf("handleDiscoveryMessage: Successfully connected to peer %s via ConnectPeer for %s", node.ID, s.localNode.Address)
			}
		}
		log.Printf("handleDiscoveryMessage: Sending peer %s to ResponseCh for %s (ChannelLen=%d)", node.ID, s.localNode.Address, len(s.nodeManager.ResponseCh))
		s.nodeManager.ResponseCh <- []*network.Peer{peer}
		log.Printf("handleDiscoveryMessage: Sent peer %s to ResponseCh for %s (ChannelLen=%d)", node.ID, s.localNode.Address, len(s.nodeManager.ResponseCh))
	case "FINDNODE":
		var findNodeData network.FindNodeData
		if err := json.Unmarshal(msg.Data, &findNodeData); err != nil {
			log.Printf("handleDiscoveryMessage: Invalid FINDNODE data from %s for %s: %v", addr.String(), s.localNode.Address, err)
			return
		}
		log.Printf("handleDiscoveryMessage: Received FINDNODE from %s for target %x for %s", addr.String(), findNodeData.TargetID[:8], s.localNode.Address)
		s.sendUDPNeighbors(addr, findNodeData.TargetID, findNodeData.Nonce)
	case "NEIGHBORS":
		var neighborsData network.NeighborsData
		if err := json.Unmarshal(msg.Data, &neighborsData); err != nil {
			log.Printf("handleDiscoveryMessage: Invalid NEIGHBORS data from %s for %s: %v", addr.String(), s.localNode.Address, err)
			return
		}
		log.Printf("handleDiscoveryMessage: Received NEIGHBORS from %s with %d peers for %s", addr.String(), len(neighborsData.Nodes), s.localNode.Address)
		peers := make([]*network.Peer, 0, len(neighborsData.Nodes))
		for _, nodeInfo := range neighborsData.Nodes {
			node := network.NewNode(nodeInfo.Address, nodeInfo.IP, nodeInfo.Port, nodeInfo.UDPPort, false, nodeInfo.Role)
			node.KademliaID = nodeInfo.KademliaID
			node.PublicKey = nodeInfo.PublicKey
			node.UpdateStatus(nodeInfo.Status)
			s.nodeManager.AddNode(node)
			log.Printf("handleDiscoveryMessage: Added node from NEIGHBORS: ID=%s, Address=%s, Role=%s, KademliaID=%x", node.ID, node.Address, node.Role, node.KademliaID[:8])
			peers = append(peers, network.NewPeer(node))
		}
		log.Printf("handleDiscoveryMessage: Sending %d peers to ResponseCh for %s (ChannelLen=%d)", len(peers), s.localNode.Address, len(s.nodeManager.ResponseCh))
		s.nodeManager.ResponseCh <- peers
		log.Printf("handleDiscoveryMessage: Sent %d peers to ResponseCh for %s (ChannelLen=%d)", len(peers), s.localNode.Address, len(s.nodeManager.ResponseCh))
	}
}

// sendUDPPing sends a PING message to a node.
func (s *Server) sendUDPPing(addr *net.UDPAddr, toID network.NodeID, nonce []byte) {
	km, err := key.NewKeyManager()
	if err != nil {
		log.Printf("sendUDPPing: Failed to initialize KeyManager for %s: %v", s.localNode.Address, err)
		return
	}
	log.Printf("sendUDPPing: Deserializing keys for node %s: PrivateKey length=%d, PublicKey length=%d", s.localNode.Address, len(s.localNode.PrivateKey), len(s.localNode.PublicKey))
	privateKey, _, err := km.DeserializeKeyPair(s.localNode.PrivateKey, s.localNode.PublicKey)
	if err != nil {
		log.Printf("sendUDPPing: Failed to deserialize key pair for %s: %v", s.localNode.Address, err)
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
		log.Printf("sendUDPPing: Failed to marshal PING data for %s to %s: %v", s.localNode.Address, addr.String(), err)
		return
	}
	log.Printf("sendUDPPing: PING data for %s to %s: %s", s.localNode.Address, addr.String(), string(dataBytes))
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(data.Timestamp.Unix()))
	signature, merkleRootNode, _, _, err := s.sphincsMgr.SignMessage(dataBytes, privateKey)
	if err != nil {
		log.Printf("sendUDPPing: Failed to sign PING message for %s to %s: %v", s.localNode.Address, addr.String(), err)
		return
	}
	signatureBytes, err := s.sphincsMgr.SerializeSignature(signature)
	if err != nil {
		log.Printf("sendUDPPing: Failed to serialize signature for %s to %s: %v", s.localNode.Address, addr.String(), err)
		return
	}
	err = hashtree.SaveLeavesToDB(s.db, [][]byte{dataBytes, signatureBytes})
	if err != nil {
		log.Printf("sendUDPPing: Failed to store signature for %s to %s: %v", s.localNode.Address, addr.String(), err)
		return
	}
	proofData := append(timestamp, append(nonce, dataBytes...)...)
	proof, err := sigproof.GenerateSigProof([][]byte{proofData}, [][]byte{merkleRootNode.Hash.Bytes()}, s.localNode.PublicKey)
	if err != nil {
		log.Printf("sendUDPPing: Failed to generate proof for PING for %s to %s: %v", s.localNode.Address, addr.String(), err)
		return
	}
	msg := network.DiscoveryMessage{
		Type:       "PING",
		Data:       dataBytes,
		PublicKey:  s.localNode.PublicKey,
		MerkleRoot: merkleRootNode.Hash, // Use *uint256.Int directly
		Proof:      proof,
		Nonce:      nonce,
		Timestamp:  timestamp,
	}
	log.Printf("sendUDPPing: Sending PING message from %s to %s: Type=%s, Nonce=%x, Timestamp=%x", s.localNode.Address, addr.String(), msg.Type, msg.Nonce[:8], msg.Timestamp)
	s.sendUDPMessage(addr, msg)
	log.Printf("sendUDPPing: Sent PING to %s (KademliaID: %x) from %s", addr.String(), toID[:8], s.localNode.Address)
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
		Nonce:     nonce,
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
	proofData := append(timestamp, append(nonce, dataBytes...)...)
	proof, err := sigproof.GenerateSigProof([][]byte{proofData}, [][]byte{merkleRootNode.Hash.Bytes()}, s.localNode.PublicKey)
	if err != nil {
		log.Printf("sendUDPPong: Failed to generate proof for PONG: %v", err)
		return
	}
	msg := network.DiscoveryMessage{
		Type:       "PONG",
		Data:       dataBytes,
		PublicKey:  s.localNode.PublicKey,
		MerkleRoot: merkleRootNode.Hash, // Use *uint256.Int directly
		Proof:      proof,
		Nonce:      nonce,
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
		Nonce:     nonce,
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
	proofData := append(timestamp, append(nonce, dataBytes...)...)
	proof, err := sigproof.GenerateSigProof([][]byte{proofData}, [][]byte{merkleRootNode.Hash.Bytes()}, s.localNode.PublicKey)
	if err != nil {
		log.Printf("sendUDPNeighbors: Failed to generate proof for NEIGHBORS: %v", err)
		return
	}
	msg := network.DiscoveryMessage{
		Type:       "NEIGHBORS",
		Data:       dataBytes,
		PublicKey:  s.localNode.PublicKey,
		MerkleRoot: merkleRootNode.Hash, // Use *uint256.Int directly
		Proof:      proof,
		Nonce:      nonce,
		Timestamp:  timestamp,
	}
	s.sendUDPMessage(addr, msg)
	log.Printf("sendUDPNeighbors: Sent NEIGHBORS to %s with %d peers", addr.String(), len(neighbors))
}

// sendUDPMessage sends a discovery message over UDP.
func (s *Server) sendUDPMessage(addr *net.UDPAddr, msg network.DiscoveryMessage) {
	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("sendUDPMessage: Failed to marshal message for %s to %s: %v", s.localNode.Address, addr.String(), err)
		return
	}
	log.Printf("sendUDPMessage: Sending message from %s to %s: %s", s.localNode.Address, addr.String(), string(data))
	// Log message size
	log.Printf("sendUDPMessage: Message size: %d bytes", len(data))
	if len(data) > 1472 {
		log.Printf("sendUDPMessage: Warning: Message size (%d bytes) exceeds typical UDP MTU (1472 bytes)", len(data))
	}
	_, err = s.udpConn.WriteToUDP(data, addr)
	if err != nil {
		log.Printf("sendUDPMessage: Failed to send message from %s to %s: %v", s.localNode.Address, addr.String(), err)
		return
	}
	log.Printf("sendUDPMessage: Successfully sent message from %s to %s", s.localNode.Address, addr.String())
}

// StoreDiscoveryMessage stores discovery message leaves in the database.
func (s *Server) StoreDiscoveryMessage(msg *network.DiscoveryMessage) error {
	return hashtree.SaveLeavesToDB(s.db, [][]byte{msg.Data})
}
