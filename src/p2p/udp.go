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
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sphinx-core/go/src/core/hashtree"
	sigproof "github.com/sphinx-core/go/src/core/proof"
	key "github.com/sphinx-core/go/src/core/sphincs/key/backend"
	"github.com/sphinx-core/go/src/network"
	"golang.org/x/sys/unix"
)

// CheckPort checks if a UDP port is available.
func CheckPort(port string) error {
	ln, err := net.ListenUDP("udp", &net.UDPAddr{Port: parsePort(port), IP: net.ParseIP("0.0.0.0")})
	if err != nil {
		return fmt.Errorf("port %s is in use: %v", port, err)
	}
	ln.Close()
	return nil
}

// StartUDPDiscovery starts the UDP server for peer discovery.
func (s *Server) StartUDPDiscovery(udpPort string) error {
	const maxRetries = 5
	originalPort := parsePort(udpPort)
	currentPort := originalPort
	var lastErr error

	for retry := 0; retry < maxRetries; retry++ {
		if err := CheckPort(strconv.Itoa(currentPort)); err != nil {
			log.Printf("StartUDPDiscovery: Port %d in use for node %s: %v", currentPort, s.localNode.Address, err)
			newPort, err := network.FindFreePort(currentPort+1, "udp")
			if err != nil {
				lastErr = fmt.Errorf("failed to find free UDP port after %s: %v", udpPort, err)
				time.Sleep(1 * time.Second) // Add delay to avoid rapid retries
				continue
			}
			currentPort = newPort
			continue
		}

		// Create UDP socket with SO_REUSEADDR
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
		if err != nil {
			lastErr = fmt.Errorf("failed to create UDP socket: %v", err)
			continue
		}
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			unix.Close(fd)
			lastErr = fmt.Errorf("failed to set SO_REUSEADDR: %v", err)
			continue
		}

		// Convert file descriptor to *os.File
		file := os.NewFile(uintptr(fd), "")
		defer file.Close() // Ensure file is closed if ListenUDP fails

		// Create UDP connection
		udpConn, err := net.FileConn(file)
		if err != nil {
			unix.Close(fd)
			lastErr = fmt.Errorf("failed to create net.Conn: %v", err)
			continue
		}
		conn, ok := udpConn.(*net.UDPConn)
		if !ok {
			udpConn.Close()
			lastErr = fmt.Errorf("failed to cast to UDPConn")
			continue
		}

		// Bind the UDP connection to the address
		listener, err := net.ListenUDP("udp", &net.UDPAddr{Port: currentPort, IP: net.ParseIP("0.0.0.0")})
		if err != nil {
			conn.Close()
			lastErr = fmt.Errorf("failed to bind UDP port %d: %v", currentPort, err)
			continue
		}

		s.udpConn = listener
		s.stopCh = make(chan struct{})
		go s.handleUDP()
		log.Printf("UDP discovery started on :%d for node %s", currentPort, s.localNode.Address)
		if s.udpReadyCh != nil {
			s.udpReadyCh <- struct{}{}
		}
		// Update local node UDP port and global config
		if currentPort != originalPort {
			s.localNode.UDPPort = strconv.Itoa(currentPort)
			log.Printf("StartUDPDiscovery: Updated node %s UDP port to %d", s.localNode.Address, currentPort)
			// Update global configuration
			// Update global configuration
			config, exists := network.GetNodeConfig(s.localNode.ID)
			if exists {
				config.UDPPort = strconv.Itoa(currentPort)
				network.UpdateNodeConfig(config)
			} else {
				log.Printf("StartUDPDiscovery: No configuration found for node ID %s", s.localNode.ID)
			}
		}
		return nil
	}

	return fmt.Errorf("failed to start UDP discovery after %d retries: %v", maxRetries, lastErr)
}

// parsePort converts a string port to an integer.
func parsePort(portStr string) int {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Printf("Invalid port %s: %v", portStr, err)
		return 0
	}
	return port
}

// StopUDPDiscovery closes the UDP connection.
func (s *Server) StopUDPDiscovery() error {
	if s.udpConn != nil {
		select {
		case <-s.stopCh:
			// Channel already closed
		default:
			close(s.stopCh)
		}
		if err := s.udpConn.Close(); err != nil {
			log.Printf("StopUDPDiscovery: Failed to close UDP connection for %s: %v", s.localNode.Address, err)
			return fmt.Errorf("failed to close UDP connection: %v", err)
		}
		s.udpConn = nil
		log.Printf("StopUDPDiscovery: UDP connection closed for %s", s.localNode.Address)
	}
	return nil
}

// handleUDP processes incoming UDP messages.
func (s *Server) handleUDP() {
	if s.udpConn == nil {
		log.Printf("handleUDP: No UDP connection for %s", s.localNode.Address)
		return
	}
	buffer := make([]byte, 65535) // 64 KB buffer
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
// Around line 150 in udp.go
func (s *Server) handleDiscoveryMessage(msg *network.DiscoveryMessage, addr *net.UDPAddr) {
	log.Printf("handleDiscoveryMessage: Received %s message from %s for node %s: Timestamp=%x, Nonce=%x", msg.Type, addr.String(), s.localNode.Address, msg.Timestamp, msg.Nonce[:8])
	// Log message size
	msgBytes, _ := json.Marshal(msg)
	log.Printf("handleDiscoveryMessage: Message size: %d bytes", len(msgBytes))
	if len(msgBytes) > 1472 {
		log.Printf("handleDiscoveryMessage: Warning: Message size (%d bytes) exceeds typical UDP MTU (1472 bytes)", len(msgBytes))
	}

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

	getTCPAddress := func(udpPort string) (string, string) {
		network.NodeConfigsLock.RLock()
		defer network.NodeConfigsLock.RUnlock()
		// Normalize udpPort (strip IP if present)
		udpParts := strings.Split(udpPort, ":")
		udpPortNorm := udpParts[len(udpParts)-1]
		for _, cfg := range network.NodeConfigs {
			cfgParts := strings.Split(cfg.UDPPort, ":")
			cfgUDPPortNorm := cfgParts[len(cfgParts)-1]
			if cfgUDPPortNorm == udpPortNorm && cfg.ID != s.localNode.ID { // Avoid self-mapping
				if cfg.TCPAddr != "" {
					parts := strings.Split(cfg.TCPAddr, ":")
					if len(parts) == 2 {
						log.Printf("handleDiscoveryMessage: Found TCP address %s for UDP port %s", cfg.TCPAddr, udpPort)
						return cfg.TCPAddr, parts[1]
					}
				}
			}
		}
		log.Printf("handleDiscoveryMessage: No TCP address found for UDP port %s", udpPort)
		return "", ""
	}

	switch msg.Type {
	case "PING":
		var pingData network.PingData
		if err := json.Unmarshal(msg.Data, &pingData); err != nil {
			log.Printf("handleDiscoveryMessage: Invalid PING data from %s for %s: %v", addr.String(), s.localNode.Address, err)
			return
		}
		tcpAddr, tcpPort := getTCPAddress(fmt.Sprintf("%d", addr.Port))
		if tcpAddr == "" {
			log.Printf("handleDiscoveryMessage: No TCP address found for PING from %s, skipping", addr.String())
			return
		}
		if tcpAddr == s.localNode.Address {
			log.Printf("handleDiscoveryMessage: Skipping PING from self (%s) for %s", addr.String(), s.localNode.Address)
			return
		}
		node := s.nodeManager.GetNodeByKademliaID(pingData.FromID)
		if node == nil {
			// FIX: Add database parameter (use nil since we don't have database access here)
			node = network.NewNode(tcpAddr, addr.IP.String(), tcpPort, fmt.Sprintf("%d", addr.Port), false, network.RoleNone, nil)
			node.KademliaID = pingData.FromID
			node.PublicKey = msg.PublicKey
			s.nodeManager.AddNode(node)
			log.Printf("handleDiscoveryMessage: Added node: ID=%s, Address=%s, Role=%s, KademliaID=%x", node.ID, node.Address, node.Role, node.KademliaID[:8])
		} else {
			node.Address = tcpAddr
			node.Port = tcpPort
			node.IP = addr.IP.String()
			node.UDPPort = fmt.Sprintf("%d", addr.Port)
			node.PublicKey = msg.PublicKey
			s.nodeManager.UpdateNode(node)
			log.Printf("handleDiscoveryMessage: Updated node: ID=%s, Address=%s, Role=%s, KademliaID=%x", node.ID, node.Address, node.Role, node.KademliaID[:8])
		}
		// Send PONG response
		s.sendUDPPong(addr, pingData.FromID, msg.Nonce)
		log.Printf("handleDiscoveryMessage: Sent PONG to %s for PING from %s", addr.String(), s.localNode.Address)

	case "PONG":
		var pongData network.PongData
		if err := json.Unmarshal(msg.Data, &pongData); err != nil {
			log.Printf("handleDiscoveryMessage: Invalid PONG data from %s for %s: %v", addr.String(), s.localNode.Address, err)
			return
		}
		log.Printf("handleDiscoveryMessage: Received PONG from %s (KademliaID: %x) for %s", addr.String(), pongData.FromID[:8], s.localNode.Address)
		tcpAddr, tcpPort := getTCPAddress(fmt.Sprintf("%d", addr.Port))
		if tcpAddr == "" {
			log.Printf("handleDiscoveryMessage: No TCP address found for PONG from %s, skipping", addr.String())
			return
		}
		if tcpAddr == s.localNode.Address {
			log.Printf("handleDiscoveryMessage: Skipping PONG from self (%s) for %s", addr.String(), s.localNode.Address)
			return
		}
		node := s.nodeManager.GetNodeByKademliaID(pongData.FromID)
		if node == nil {
			// FIX: Add database parameter (use nil since we don't have database access here)
			node = network.NewNode(tcpAddr, addr.IP.String(), tcpPort, fmt.Sprintf("%d", addr.Port), false, network.RoleNone, nil)
			node.KademliaID = pongData.FromID
			node.PublicKey = msg.PublicKey
			s.nodeManager.AddNode(node)
			log.Printf("handleDiscoveryMessage: Added node: ID=%s, Address=%s, Role=%s, KademliaID=%x", node.ID, node.Address, node.Role, node.KademliaID[:8])
		} else {
			node.Address = tcpAddr
			node.Port = tcpPort
			node.IP = addr.IP.String()
			node.UDPPort = fmt.Sprintf("%d", addr.Port)
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

	case "NEIGHBORS":
		var neighborsData network.NeighborsData
		if err := json.Unmarshal(msg.Data, &neighborsData); err != nil {
			log.Printf("handleDiscoveryMessage: Invalid NEIGHBORS data from %s for %s: %v", addr.String(), s.localNode.Address, err)
			return
		}
		log.Printf("handleDiscoveryMessage: Received NEIGHBORS from %s with %d peers for %s", addr.String(), len(neighborsData.Nodes), s.localNode.Address)
		peers := make([]*network.Peer, 0, len(neighborsData.Nodes))
		for _, nodeInfo := range neighborsData.Nodes {
			// FIX: Add database parameter (use nil since we don't have database access here)
			node := network.NewNode(nodeInfo.Address, nodeInfo.IP, nodeInfo.Port, nodeInfo.UDPPort, false, nodeInfo.Role, nil)
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
		log.Printf("sendUDPPong: Failed to initialize KeyManager for %s: %v", s.localNode.Address, err)
		return
	}
	log.Printf("sendUDPPong: Deserializing keys for node %s: PrivateKey length=%d, PublicKey length=%d", s.localNode.Address, len(s.localNode.PrivateKey), len(s.localNode.PublicKey))
	privateKey, _, err := km.DeserializeKeyPair(s.localNode.PrivateKey, s.localNode.PublicKey)
	if err != nil {
		log.Printf("sendUDPPong: Failed to deserialize key pair for %s: %v", s.localNode.Address, err)
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
		log.Printf("sendUDPPong: Failed to marshal PONG data for %s to %s: %v", s.localNode.Address, addr.String(), err)
		return
	}
	log.Printf("sendUDPPong: PONG data for %s to %s: %s", s.localNode.Address, addr.String(), string(dataBytes))
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(data.Timestamp.Unix()))
	signature, merkleRootNode, _, _, err := s.sphincsMgr.SignMessage(dataBytes, privateKey)
	if err != nil {
		log.Printf("sendUDPPong: Failed to sign PONG message for %s to %s: %v", s.localNode.Address, addr.String(), err)
		return
	}
	signatureBytes, err := s.sphincsMgr.SerializeSignature(signature)
	if err != nil {
		log.Printf("sendUDPPong: Failed to serialize signature for %s to %s: %v", s.localNode.Address, addr.String(), err)
		return
	}
	err = hashtree.SaveLeavesToDB(s.db, [][]byte{dataBytes, signatureBytes})
	if err != nil {
		log.Printf("sendUDPPong: Failed to store signature for %s to %s: %v", s.localNode.Address, addr.String(), err)
		return
	}
	proofData := append(timestamp, append(nonce, dataBytes...)...)
	proof, err := sigproof.GenerateSigProof([][]byte{proofData}, [][]byte{merkleRootNode.Hash.Bytes()}, s.localNode.PublicKey)
	if err != nil {
		log.Printf("sendUDPPong: Failed to generate proof for PONG for %s to %s: %v", s.localNode.Address, addr.String(), err)
		return
	}
	msg := network.DiscoveryMessage{
		Type:       "PONG",
		Data:       dataBytes,
		PublicKey:  s.localNode.PublicKey,
		MerkleRoot: merkleRootNode.Hash,
		Proof:      proof,
		Nonce:      nonce,
		Timestamp:  timestamp,
	}
	s.sendUDPMessage(addr, msg)
	log.Printf("sendUDPPong: Sent PONG to %s (KademliaID: %x) from %s", addr.String(), toID[:8], s.localNode.Address)
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
