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
	"encoding/json"
	"log"
	"net"
	"time"

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
	km, err := key.NewKeyManager()
	if err != nil {
		log.Printf("Failed to initialize key manager: %v", err)
		return
	}
	dataBytes, _ := json.Marshal(msg.Data)
	if !km.Verify(msg.PublicKey, dataBytes, msg.Signature) {
		log.Printf("Invalid signature for %s message from %s", msg.Type, addr.String())
		return
	}
	switch msg.Type {
	case "PING":
		var pingData network.PingData
		if err := json.Unmarshal(dataBytes, &pingData); err != nil {
			log.Printf("Invalid PING data: %v", err)
			return
		}
		s.sendUDPPong(addr, pingData.FromID)
		node := s.nodeManager.GetNodeByKademliaID(pingData.FromID)
		if node == nil {
			node = network.NewNode(addr.String(), addr.IP.String(), "", addr.String(), false, network.RoleNone)
			node.KademliaID = pingData.FromID
			node.PublicKey = msg.PublicKey
			s.nodeManager.AddNode(node)
		}
		node.UpdateStatus(network.NodeStatusActive)
	case "PONG":
		var pongData network.PongData
		if err := json.Unmarshal(dataBytes, &pongData); err != nil {
			log.Printf("Invalid PONG data: %v", err)
			return
		}
		if peer := s.nodeManager.GetNodeByKademliaID(pongData.FromID); peer != nil {
			if p, exists := s.nodeManager.GetPeers()[peer.ID]; exists {
				p.ReceivePong()
			}
		}
	case "FINDNODE":
		var findNodeData network.FindNodeData
		if err := json.Unmarshal(dataBytes, &findNodeData); err != nil {
			log.Printf("Invalid FINDNODE data: %v", err)
			return
		}
		s.sendUDPNeighbors(addr, findNodeData.TargetID)
	case "NEIGHBORS":
		var neighborsData network.NeighborsData
		if err := json.Unmarshal(dataBytes, &neighborsData); err != nil {
			log.Printf("Invalid NEIGHBORS data: %v", err)
			return
		}
		peers := make([]*network.Peer, 0, len(neighborsData.Nodes))
		for _, nodeInfo := range neighborsData.Nodes {
			node := network.NewNode(nodeInfo.Address, nodeInfo.IP, nodeInfo.Port, nodeInfo.UDPPort, false, nodeInfo.Role)
			node.KademliaID = nodeInfo.KademliaID
			node.PublicKey = nodeInfo.PublicKey
			node.UpdateStatus(nodeInfo.Status)
			s.nodeManager.AddNode(node)
			peers = append(peers, network.NewPeer(node))
		}
		s.nodeManager.ResponseCh <- peers // Send to response channel
	}
}

// sendUDPPing sends a PING message to a node.
func (s *Server) sendUDPPing(addr *net.UDPAddr, toID network.NodeID) {
	km, err := key.NewKeyManager()
	if err != nil {
		log.Printf("Failed to initialize key manager: %v", err)
		return
	}
	data := network.PingData{
		FromID:    s.localNode.KademliaID,
		ToID:      toID,
		Timestamp: time.Now(),
	}
	dataBytes, _ := json.Marshal(data)
	signature, err := km.Sign(s.localNode.PrivateKey, dataBytes)
	if err != nil {
		log.Printf("Failed to sign PING message: %v", err)
		return
	}
	msg := network.DiscoveryMessage{
		Type:      "PING",
		Data:      data,
		Signature: signature,
		PublicKey: s.localNode.PublicKey,
	}
	s.sendUDPMessage(addr, msg)
}

// sendUDPPong sends a PONG message in response to a PING.
func (s *Server) sendUDPPong(addr *net.UDPAddr, toID network.NodeID) {
	km, err := key.NewKeyManager()
	if err != nil {
		log.Printf("Failed to initialize key manager: %v", err)
		return
	}
	data := network.PongData{
		FromID:    s.localNode.KademliaID,
		ToID:      toID,
		Timestamp: time.Now(),
	}
	dataBytes, _ := json.Marshal(data)
	signature, err := km.Sign(s.localNode.PrivateKey, dataBytes)
	if err != nil {
		log.Printf("Failed to sign PONG message: %v", err)
		return
	}
	msg := network.DiscoveryMessage{
		Type:      "PONG",
		Data:      data,
		Signature: signature,
		PublicKey: s.localNode.PublicKey,
	}
	s.sendUDPMessage(addr, msg)
}

// sendUDPNeighbors sends a NEIGHBORS message with closest peers.
func (s *Server) sendUDPNeighbors(addr *net.UDPAddr, targetID network.NodeID) {
	peers := s.nodeManager.FindClosestPeers(targetID, s.nodeManager.K)
	neighbors := make([]network.PeerInfo, 0, len(peers))
	for _, peer := range peers {
		neighbors = append(neighbors, peer.GetPeerInfo())
	}
	km, err := key.NewKeyManager()
	if err != nil {
		log.Printf("Failed to initialize key manager: %v", err)
		return
	}
	data := network.NeighborsData{Nodes: neighbors}
	dataBytes, _ := json.Marshal(data)
	signature, err := km.Sign(s.localNode.PrivateKey, dataBytes)
	if err != nil {
		log.Printf("Failed to sign NEIGHBORS message: %v", err)
		return
	}
	msg := network.DiscoveryMessage{
		Type:      "NEIGHBORS",
		Data:      data,
		Signature: signature,
		PublicKey: s.localNode.PublicKey,
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
