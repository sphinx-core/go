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

// go/src/transport/ip.go
package transport

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/sphinx-core/go/src/network"
	"github.com/sphinx-core/go/src/security"
)

func ValidateIP(ip, port string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	if _, err := net.LookupPort("tcp", port); err != nil {
		return fmt.Errorf("invalid port: %s", port)
	}
	return nil
}

func ResolveAddress(ip, port string) (string, error) {
	if err := ValidateIP(ip, port); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s:%s", ip, port), nil
}

func NodeToAddress(node *network.Node) (string, error) {
	if node.IP == "" || node.Port == "" {
		return "", fmt.Errorf("node %s has empty IP or port", node.ID)
	}
	return ResolveAddress(node.IP, node.Port)
}

func ConnectNode(node *network.Node, messageCh chan *security.Message) error {
	addr, err := NodeToAddress(node)
	if err != nil {
		return err
	}

	for attempt := 1; attempt <= 3; attempt++ {
		if err := ConnectTCP(addr, messageCh); err == nil {
			node.UpdateStatus(network.NodeStatusActive)
			log.Printf("Connected to node %s via TCP: %s", node.ID, addr)
			return nil
		}
		log.Printf("TCP connection to node %s (%s) attempt %d failed: %v", node.ID, addr, attempt, err)

		wsAddr := fmt.Sprintf("%s:%d", node.IP, parsePort(node.Port)+553)
		if err := ConnectWebSocket(wsAddr, messageCh); err == nil {
			node.UpdateStatus(network.NodeStatusActive)
			log.Printf("Connected to node %s via WebSocket: %s", node.ID, wsAddr)
			return nil
		}
		log.Printf("WebSocket connection to node %s (%s) attempt %d failed: %v", node.ID, wsAddr, attempt, err)

		if attempt < 3 {
			time.Sleep(time.Second * time.Duration(attempt))
		}
	}
	return fmt.Errorf("failed to connect to node %s (%s) after 3 attempts", node.ID, addr)
}

func parsePort(port string) int {
	p, err := net.LookupPort("tcp", port)
	if err != nil {
		return 0
	}
	return p
}

func SendPeerInfo(address string, peerInfo *network.PeerInfo) error {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to dial connection to %s: %v", address, err)
	}
	defer conn.Close()

	handshake := security.NewHandshake()
	ek, err := handshake.PerformHandshake(conn, "tcp", true)
	if err != nil {
		return err
	}

	msg := &security.Message{Type: "peer_info", Data: *peerInfo}
	data, err := security.SecureMessage(msg, ek)
	if err != nil {
		return fmt.Errorf("failed to encode PeerInfo message: %v", err)
	}
	if _, err := conn.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("failed to write PeerInfo to %s: %v", address, err)
	}
	log.Printf("Sent PeerInfo to %s", address)
	return nil
}
