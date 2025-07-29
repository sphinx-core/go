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

	security "github.com/sphinx-core/go/src/handshake"
	"github.com/sphinx-core/go/src/network"
)

// ValidateIP checks whether the provided IP and port are valid.
func ValidateIP(ip, port string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip) // Validate the IP address format
	}
	if _, err := net.LookupPort("tcp", port); err != nil {
		return fmt.Errorf("invalid port: %s", port) // Validate the TCP port
	}
	return nil // Return nil if both IP and port are valid
}

// ResolveAddress constructs a full address string from a validated IP and port.
func ResolveAddress(ip, port string) (string, error) {
	if err := ValidateIP(ip, port); err != nil {
		return "", err // Return an error if validation fails
	}
	return fmt.Sprintf("%s:%s", ip, port), nil // Return formatted address string
}

// NodeToAddress converts a network.Node's IP and Port into a usable address string.
// NodeToAddress converts a Node to a TCP address.
func NodeToAddress(node *network.Node) (string, error) {
	if node.IP == "" || node.Port == "" {
		log.Printf("NodeToAddress: node %s has empty IP=%s or Port=%s", node.ID, node.IP, node.Port)
		return "", fmt.Errorf("node %s has empty IP or port", node.ID)
	}
	return fmt.Sprintf("%s:%s", node.IP, node.Port), nil
}

// ConnectNode attempts to connect to a node using TCP and WebSocket up to 3 times.
func ConnectNode(node *network.Node, messageCh chan *security.Message) error {
	addr, err := NodeToAddress(node) // Convert node to address string
	if err != nil {
		return err // Return if address resolution fails
	}

	for attempt := 1; attempt <= 3; attempt++ { // Retry up to 3 times
		conn, err := ConnectTCP(addr, messageCh)
		if err == nil {
			defer conn.Close()
			node.UpdateStatus(network.NodeStatusActive)
			log.Printf("Connected to node %s via TCP: %s", node.ID, addr)
			return nil
		}
		log.Printf("TCP connection to node %s (%s) attempt %d failed: %v", node.ID, addr, attempt, err) // Log TCP failure

		wsAddr := fmt.Sprintf("%s:%d", node.IP, parsePort(node.Port)+553) // Construct WebSocket fallback address
		if err := ConnectWebSocket(wsAddr, messageCh); err == nil {
			node.UpdateStatus(network.NodeStatusActive)                           // Mark node as active on WebSocket success
			log.Printf("Connected to node %s via WebSocket: %s", node.ID, wsAddr) // Log WebSocket connection success
			return nil
		}
		log.Printf("WebSocket connection to node %s (%s) attempt %d failed: %v", node.ID, wsAddr, attempt, err) // Log WebSocket failure

		if attempt < 3 {
			time.Sleep(time.Second * time.Duration(attempt)) // Exponential backoff between retries
		}
	}
	return fmt.Errorf("failed to connect to node %s (%s) after 3 attempts", node.ID, addr) // Return error after 3 failed attempts
}

// parsePort resolves a port string to its integer value using TCP lookup.
func parsePort(port string) int {
	p, err := net.LookupPort("tcp", port) // Attempt to resolve TCP port number
	if err != nil {
		return 0 // Return 0 if port resolution fails
	}
	return p // Return resolved port number
}

// SendPeerInfo sends a PeerInfo message to the given address over a secure TCP connection.
func SendPeerInfo(address string, peerInfo *network.PeerInfo) error {
	conn, err := net.Dial("tcp", address) // Dial TCP connection to the address
	if err != nil {
		return fmt.Errorf("failed to dial connection to %s: %v", address, err) // Return error if dialing fails
	}
	defer conn.Close() // Ensure connection is closed after function ends

	handshake := security.NewHandshake()                     // Initialize new Kyber768 handshake
	ek, err := handshake.PerformHandshake(conn, "tcp", true) // Perform key exchange as initiator
	if err != nil {
		return err // Return error if handshake fails
	}

	msg := &security.Message{Type: "peer_info", Data: *peerInfo} // Create a new peer_info message
	data, err := security.SecureMessage(msg, ek)                 // Encrypt and encode the message using the handshake key
	if err != nil {
		return fmt.Errorf("failed to encode PeerInfo message: %v", err) // Return error if encryption fails
	}

	if _, err := conn.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("failed to write PeerInfo to %s: %v", address, err) // Return error if write fails
	}
	log.Printf("Sent PeerInfo to %s", address) // Log successful PeerInfo send
	return nil                                 // Return nil on success
}
