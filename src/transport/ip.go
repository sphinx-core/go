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
	"crypto/tls"
	"fmt"
	"log"
	"net"

	"github.com/sphinx-core/go/src/network"
	"github.com/sphinx-core/go/src/security"
)

// IPConfig represents IP configuration for a node.
type IPConfig struct {
	IP   string // IP address (e.g., "192.168.1.1")
	Port string // Port number (e.g., "8080")
}

// ValidateIP validates an IP address and port.
func ValidateIP(ip, port string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	if _, err := net.LookupPort("tcp", port); err != nil {
		return fmt.Errorf("invalid port: %s", port)
	}
	return nil
}

// ResolveAddress resolves an IP:port pair into a network address.
func ResolveAddress(ip, port string) (string, error) {
	if err := ValidateIP(ip, port); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s:%s", ip, port), nil
}

// NodeToAddress converts a network.Node to a usable address.
func NodeToAddress(node *network.Node) (string, error) {
	if node.IP == "" || node.Port == "" {
		return "", fmt.Errorf("node %s has empty IP or port", node.ID)
	}
	return ResolveAddress(node.IP, node.Port)
}

// ConnectNode establishes a connection to a node using its IP configuration.
func ConnectNode(node *network.Node, messageCh chan *security.Message) error {
	addr, err := NodeToAddress(node)
	if err != nil {
		return err
	}
	// Try TCP first
	if err := ConnectTCP(addr, messageCh); err != nil {
		log.Printf("TCP connection to node %s (%s) failed: %v", node.ID, addr, err)
		// Fall back to WebSocket
		if err := ConnectWebSocket(addr, messageCh); err != nil {
			log.Printf("WebSocket connection to node %s (%s) failed: %v", node.ID, addr, err)
			return err
		}
	}
	node.UpdateStatus(network.NodeStatusActive)
	log.Printf("Connected to node %s (%s)", node.ID, addr)
	return nil
}

// SendPeerInfo sends PeerInfo to a specific address.
func SendPeerInfo(address string, peerInfo *network.PeerInfo) error {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // For testing; remove in production
		CurvePreferences:   []tls.CurveID{tls.X25519},
		MinVersion:         tls.VersionTLS13,
	}
	conn, err := tls.Dial("tcp", address, tlsConfig)
	if err != nil {
		return err
	}
	defer conn.Close()

	msg := &security.Message{Type: "peer_info", Data: peerInfo}
	data, err := msg.Encode()
	if err != nil {
		return err
	}
	if _, err := conn.Write(data); err != nil {
		return err
	}
	log.Printf("Sent PeerInfo to %s", address)
	return nil
}
