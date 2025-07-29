// MIT License
//
// # Copyright (c) 2024 sphinx-core
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

// go/src/transport/tcp.go
package transport

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	security "github.com/sphinx-core/go/src/handshake"
	"github.com/sphinx-core/go/src/network"
	"github.com/sphinx-core/go/src/rpc"
)

// Global server instance for connection management.
var globalServer = &TCPServer{
	connections: make(map[string]net.Conn),
	encKeys:     make(map[string]*security.EncryptionKey),
	mu:          sync.Mutex{},
}

// NewTCPServer creates a new TCP server.
func NewTCPServer(address string, messageCh chan *security.Message, rpcServer *rpc.Server, tcpReadyCh chan struct{}) *TCPServer {
	return &TCPServer{
		address:     address,
		messageCh:   messageCh,
		rpcServer:   rpcServer,
		handshake:   security.NewHandshake(),
		tcpReadyCh:  tcpReadyCh,
		connections: make(map[string]net.Conn),
		encKeys:     make(map[string]*security.EncryptionKey),
	}
}

// Start starts the TCP server.
func (s *TCPServer) Start() error {
	listener, err := net.Listen("tcp", s.address)
	if err != nil {
		log.Printf("Failed to bind TCP listener on %s: %v", s.address, err)
		return fmt.Errorf("failed to bind TCP listener on %s: %v", s.address, err)
	}
	s.listener = listener
	log.Printf("TCP server successfully bound to %s", s.address)
	if s.tcpReadyCh != nil {
		log.Printf("Sending TCP ready signal for %s", s.address)
		s.tcpReadyCh <- struct{}{}
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				s.handshake.Metrics.Errors.WithLabelValues("tcp").Inc()
				log.Printf("TCP accept error on %s: %v", s.address, err)
				continue
			}
			// Use the server's address as the key (e.g., 127.0.0.1:30307)
			log.Printf("Accepted new connection on %s from %s", s.address, conn.RemoteAddr().String())
			go s.handleConnection(conn, s.address)
		}
	}()
	return nil
}

// handleConnection processes messages from a TCP connection.
func (s *TCPServer) handleConnection(conn net.Conn, nodeAddr string) {
	defer func() {
		s.mu.Lock()
		delete(s.connections, nodeAddr)
		delete(s.encKeys, nodeAddr)
		s.mu.Unlock()
		if err := conn.Close(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			log.Printf("Error closing connection to %s: %v", nodeAddr, err)
		}
		log.Printf("Connection closed for %s", nodeAddr)
	}()

	enc, err := s.handshake.PerformHandshake(conn, "p2p", false)
	if err != nil {
		log.Printf("TCP handshake failed on %s: %v", nodeAddr, err)
		return
	}
	if enc == nil {
		log.Printf("TCP handshake returned nil encryption key on %s", nodeAddr)
		return
	}

	// Store the connection and encryption key
	s.mu.Lock()
	s.connections[nodeAddr] = conn
	s.encKeys[nodeAddr] = enc
	s.mu.Unlock()
	log.Printf("Handshake completed for %s, storing connection", nodeAddr)

	reader := bufio.NewReader(conn)
	for {
		lengthBuf := make([]byte, 4)
		if _, err := io.ReadFull(reader, lengthBuf); err != nil {
			if err == io.EOF {
				log.Printf("Connection closed by remote node %s: EOF", nodeAddr)
			} else if strings.Contains(err.Error(), "closed") {
				log.Printf("Connection closed by remote node %s: %v", nodeAddr, err)
			} else {
				log.Printf("TCP read length error on %s: %v", nodeAddr, err)
			}
			return
		}
		length := binary.BigEndian.Uint32(lengthBuf)
		if length > 1024*1024 {
			log.Printf("TCP message too large on %s: %d bytes", nodeAddr, length)
			return
		}

		data := make([]byte, length)
		if _, err := io.ReadFull(reader, data); err != nil {
			if err == io.EOF {
				log.Printf("Connection closed by remote node %s: EOF", nodeAddr)
			} else if strings.Contains(err.Error(), "closed") {
				log.Printf("Connection closed by remote node %s: %v", nodeAddr, err)
			} else {
				log.Printf("TCP read data error on %s: %v", nodeAddr, err)
			}
			return
		}
		log.Printf("Received raw data on %s, length: %d", nodeAddr, length)

		msg, err := security.DecodeSecureMessage(data, enc)
		if err != nil {
			log.Printf("TCP decode error on %s: %v, raw data: %x", nodeAddr, err, data)
			continue
		}
		log.Printf("Decoded message on %s: Type=%s, Data=%v", nodeAddr, msg.Type, msg.Data)

		// Handle version message and send verack response
		if msg.Type == "version" {
			// Validate version message
			versionData, ok := msg.Data.(map[string]interface{})
			if !ok {
				log.Printf("Invalid version message data on %s: %v", nodeAddr, msg.Data)
				continue
			}
			peerID, ok := versionData["node_id"].(string)
			if !ok {
				log.Printf("Invalid node_id in version message on %s", nodeAddr)
				continue
			}

			// Send verack response
			verackMsg := &security.Message{
				Type: "verack",
				Data: peerID, // Echo back the node_id
			}
			encryptedVerack, err := security.SecureMessage(verackMsg, enc)
			if err != nil {
				log.Printf("Failed to encode verack message for %s: %v", nodeAddr, err)
				continue
			}
			lengthBuf = make([]byte, 4)
			binary.BigEndian.PutUint32(lengthBuf, uint32(len(encryptedVerack)))
			if _, err := conn.Write(lengthBuf); err != nil {
				log.Printf("TCP write length error for verack on %s: %v", nodeAddr, err)
				return
			}
			if _, err := conn.Write(encryptedVerack); err != nil {
				log.Printf("TCP write data error for verack on %s: %v", nodeAddr, err)
				return
			}
			log.Printf("Sent verack to %s for node_id: %s", nodeAddr, peerID)
		}

		// Forward message to messageCh
		select {
		case s.messageCh <- msg:
			log.Printf("Forwarded message to messageCh: Type=%s, SourceAddr=%s", msg.Type, nodeAddr)
		default:
			log.Printf("Failed to forward message to messageCh: Type=%s, SourceAddr=%s, channel full", msg.Type, nodeAddr)
		}

		if msg.Type == "jsonrpc" {
			resp, err := s.rpcServer.HandleRequest([]byte(msg.Data.(string)))
			if err != nil {
				log.Printf("RPC handle error on %s: %v", nodeAddr, err)
				continue
			}
			encryptedResp, err := security.SecureMessage(&security.Message{Type: "jsonrpc", Data: string(resp)}, enc)
			if err != nil {
				log.Printf("TCP encode response error on %s: %v", nodeAddr, err)
				continue
			}
			lengthBuf = make([]byte, 4)
			binary.BigEndian.PutUint32(lengthBuf, uint32(len(encryptedResp)))
			if _, err := conn.Write(lengthBuf); err != nil {
				log.Printf("TCP write length error on %s: %v", nodeAddr, err)
				return
			}
			if _, err := conn.Write(encryptedResp); err != nil {
				log.Printf("TCP write data error on %s: %v", nodeAddr, err)
				return
			}
		}
	}
}

// Stop closes the TCP server.
func (s *TCPServer) Stop() error {
	if s.listener != nil {
		err := s.listener.Close()
		if err != nil {
			return fmt.Errorf("failed to close TCP listener on %s: %v", s.address, err)
		}
		log.Printf("TCP server on %s stopped", s.address)
	}
	return nil
}

// ConnectTCP establishes a TCP connection with handshake.
func ConnectTCP(address string, messageCh chan *security.Message) (net.Conn, error) {
	if address == "" {
		log.Printf("ConnectTCP: Empty address provided")
		return nil, fmt.Errorf("empty address provided")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for attempt := 1; attempt <= 10; attempt++ {
		select {
		case <-ctx.Done():
			log.Printf("Overall timeout connecting to %s after %d attempts: %v", address, attempt, ctx.Err())
			return nil, fmt.Errorf("timeout connecting to %s after %d attempts: %v", address, attempt, ctx.Err())
		default:
			conn, err := net.DialTimeout("tcp", address, 2*time.Second)
			if err != nil {
				sleepDuration := time.Second * time.Duration(1<<min(attempt-1, 4))
				log.Printf("TCP connection error: %s attempt %d failed: %v, retrying in %v", address, attempt, err, sleepDuration)
				time.Sleep(sleepDuration)
				continue
			}

			handshake := security.NewHandshake()
			enc, err := handshake.PerformHandshake(conn, "p2p", true)
			if err != nil {
				log.Printf("TCP handshake failed for %s on attempt %d: %v", address, attempt, err)
				conn.Close()
				continue
			}
			if enc == nil {
				log.Printf("TCP handshake returned nil encryption key for %s on attempt %d", address, attempt)
				conn.Close()
				continue
			}
			log.Printf("Handshake successful for %s", address)

			// Store the connection and encryption key
			globalServer.mu.Lock()
			globalServer.connections[address] = conn
			globalServer.encKeys[address] = enc
			globalServer.mu.Unlock()

			// Start background goroutine to read responses
			go func(conn net.Conn, address string) { // Remove cancel from goroutine
				defer func() {
					globalServer.mu.Lock()
					delete(globalServer.connections, address)
					delete(globalServer.encKeys, address)
					globalServer.mu.Unlock()
					if err := conn.Close(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
						log.Printf("Error closing connection to %s: %v", address, err)
					}
				}()

				reader := bufio.NewReader(conn)
				for {
					lengthBuf := make([]byte, 4)
					if _, err := io.ReadFull(reader, lengthBuf); err != nil {
						if err != io.EOF && !strings.Contains(err.Error(), "closed") {
							log.Printf("TCP read length error on %s: %v", address, err)
						}
						return
					}
					length := binary.BigEndian.Uint32(lengthBuf)
					if length > 1024*1024 {
						log.Printf("TCP response too large on %s: %d bytes", address, length)
						return
					}
					respData := make([]byte, length)
					if _, err := io.ReadFull(reader, respData); err != nil {
						if err != io.EOF && !strings.Contains(err.Error(), "closed") {
							log.Printf("TCP read data error on %s: %v", address, err)
						}
						return
					}
					respMsg, err := security.DecodeSecureMessage(respData, enc)
					if err != nil {
						log.Printf("TCP decode response error on %s: %v", address, err)
						continue
					}
					select {
					case messageCh <- respMsg:
						log.Printf("Sent response to messageCh for %s, message type: %s", address, respMsg.Type)
					default:
						log.Printf("Failed to send response to messageCh for %s, channel full", address)
					}
				}
			}(conn, address)

			log.Printf("TCP connected to %s", address)
			return conn, nil
		}
	}

	log.Printf("Failed to connect to %s after 10 attempts", address)
	return nil, fmt.Errorf("failed to connect to %s after 10 attempts", address)
}

// GetConnection retrieves an active TCP connection.
func GetConnection(address string) (net.Conn, error) {
	globalServer.mu.Lock()
	defer globalServer.mu.Unlock()
	conn, exists := globalServer.connections[address]
	if !exists {
		return nil, fmt.Errorf("no active connection to %s", address)
	}
	return conn, nil
}

// GetEncryptionKey retrieves the encryption key for a connection.
func GetEncryptionKey(address string) (*security.EncryptionKey, error) {
	globalServer.mu.Lock()
	defer globalServer.mu.Unlock()
	enc, exists := globalServer.encKeys[address]
	if !exists {
		return nil, fmt.Errorf("no encryption key for %s", address)
	}
	return enc, nil
}

// SendMessage sends a message to a node.
func SendMessage(address string, msg *security.Message) error {
	conn, err := GetConnection(address)
	if err != nil {
		// Fallback to establishing a new connection
		log.Printf("No active connection to %s, establishing new connection", address)
		conn, err = net.DialTimeout("tcp", address, 2*time.Second)
		if err != nil {
			return fmt.Errorf("failed to dial %s: %v", address, err)
		}
		defer conn.Close()

		handshake := security.NewHandshake()
		enc, err := handshake.PerformHandshake(conn, "p2p", true)
		if err != nil {
			return fmt.Errorf("handshake failed for %s: %v", address, err)
		}
		if enc == nil {
			return fmt.Errorf("handshake returned nil encryption key for %s", address)
		}

		// Store the new connection and key
		globalServer.mu.Lock()
		globalServer.connections[address] = conn
		globalServer.encKeys[address] = enc
		globalServer.mu.Unlock()

		data, err := security.SecureMessage(msg, enc)
		if err != nil {
			return fmt.Errorf("failed to encode message for %s: %v", address, err)
		}
		lengthBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lengthBuf, uint32(len(data)))
		if _, err := conn.Write(lengthBuf); err != nil {
			return fmt.Errorf("failed to write length to %s: %v", address, err)
		}
		log.Printf("Sending message to %s, length: %d", address, len(data))
		if _, err := conn.Write(data); err != nil {
			return fmt.Errorf("failed to write data to %s: %v", address, err)
		}
	} else {
		// Use existing connection and encryption key
		enc, err := GetEncryptionKey(address)
		if err != nil {
			return fmt.Errorf("failed to get encryption key for %s: %v", address, err)
		}
		data, err := security.SecureMessage(msg, enc)
		if err != nil {
			return fmt.Errorf("failed to encode message for %s: %v", address, err)
		}
		lengthBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lengthBuf, uint32(len(data)))
		if _, err := conn.Write(lengthBuf); err != nil {
			return fmt.Errorf("failed to write length to %s: %v", address, err)
		}
		log.Printf("Sending message to %s, length: %d", address, len(data))
		if _, err := conn.Write(data); err != nil {
			return fmt.Errorf("failed to write data to %s: %v", address, err)
		}
	}
	log.Printf("Sent message to %s: Type=%s", address, msg.Type)
	return nil
}

// DisconnectNode closes the connection to a node.
func DisconnectNode(node *network.Node) error {
	addr, err := NodeToAddress(node)
	if err != nil {
		return fmt.Errorf("invalid node address: %v", err)
	}
	globalServer.mu.Lock()
	defer globalServer.mu.Unlock()
	conn, exists := globalServer.connections[addr]
	if !exists {
		return fmt.Errorf("no connection to %s", addr)
	}
	if err := conn.Close(); err != nil {
		log.Printf("Failed to close connection to %s: %v", addr, err)
	}
	delete(globalServer.connections, addr)
	delete(globalServer.encKeys, addr)
	log.Printf("Disconnected from node %s at %s", node.ID, addr)
	return nil
}

// min returns the minimum of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
