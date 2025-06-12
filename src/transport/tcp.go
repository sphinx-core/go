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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/sphinx-core/go/src/rpc"
	"github.com/sphinx-core/go/src/security"
)

// NewTCPServer creates a new TCP server.
func NewTCPServer(address string, messageCh chan *security.Message, tlsConfig *tls.Config, rpcServer *rpc.Server) *TCPServer {
	return &TCPServer{
		address:   address,
		messageCh: messageCh,
		tlsConfig: tlsConfig,
		rpcServer: rpcServer,
		handshake: security.NewHandshake(tlsConfig),
	}
}

// Start runs the TCP server.
func (s *TCPServer) Start() error {
	listener, err := tls.Listen("tcp", s.address, s.tlsConfig)
	if err != nil {
		log.Printf("Failed to bind TCP listener on %s: %v", s.address, err)
		return err
	}
	s.listener = listener
	log.Printf("TCP server successfully bound and listening on %s", s.address)

	for {
		conn, err := listener.Accept()
		if err != nil {
			s.handshake.Metrics.Errors.WithLabelValues("tcp").Inc()
			log.Printf("TCP accept error on %s: %v", s.address, err)
			continue
		}
		go s.handleConnection(conn)
	}
}

// handleConnection processes incoming TCP connections.
func (s *TCPServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	if err := s.handshake.PerformHandshake(conn, "tcp"); err != nil {
		log.Printf("TCP handshake failed on %s: %v", s.address, err)
		return
	}

	reader := bufio.NewReader(conn)
	for {
		data, err := reader.ReadBytes('\n') // Read until newline delimiter
		if err != nil {
			log.Printf("TCP read error on %s: %v", s.address, err)
			return
		}

		var msg security.Message
		if err := json.Unmarshal(data, &msg); err != nil {
			log.Printf("TCP decode error on %s: %v", s.address, err)
			continue
		}
		s.messageCh <- &msg

		if msg.Type == "jsonrpc" {
			resp, err := s.rpcServer.HandleRequest([]byte(msg.Data.(string)))
			if err != nil {
				log.Printf("RPC handle error on %s: %v", s.address, err)
				continue
			}
			respData, err := json.Marshal(resp)
			if err != nil {
				log.Printf("TCP encode response error on %s: %v", s.address, err)
				continue
			}
			if _, err := conn.Write(append(respData, '\n')); err != nil {
				log.Printf("TCP write error on %s: %v", s.address, err)
				return
			}
		}
	}
}

// ConnectTCP establishes a TLS-secured TCP connection to a peer.
func ConnectTCP(address string, messageCh chan *security.Message) error {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // For testing
		CurvePreferences:   []tls.CurveID{tls.X25519},
		MinVersion:         tls.VersionTLS13,
	}

	for attempt := 1; attempt <= 5; attempt++ {
		conn, err := tls.Dial("tcp", address, tlsConfig)
		if err == nil {
			defer conn.Close()

			// Perform handshake
			handshake := security.NewHandshake(tlsConfig)
			if err := handshake.PerformHandshake(conn, "tcp"); err != nil {
				log.Printf("TCP handshake failed for %s on attempt %d: %v", address, attempt, err)
				continue
			}

			// Send example message
			msg := &security.Message{Type: "ping", Data: "hello"}
			data, err := json.Marshal(msg)
			if err != nil {
				log.Printf("TCP encode error for %s on attempt %d: %v", address, attempt, err)
				continue
			}
			if _, err := conn.Write(append(data, '\n')); err != nil {
				log.Printf("TCP write error for %s on attempt %d: %v", address, attempt, err)
				continue
			}

			// Read response
			reader := bufio.NewReader(conn)
			respData, err := reader.ReadBytes('\n')
			if err != nil {
				log.Printf("TCP read response error for %s on attempt %d: %v", address, attempt, err)
				continue
			}
			var respMsg security.Message
			if err := json.Unmarshal(respData, &respMsg); err != nil {
				log.Printf("TCP decode response error for %s on attempt %d: %v", address, attempt, err)
				continue
			}
			messageCh <- &respMsg

			log.Printf("TCP connected to %s", address)
			return nil
		}
		log.Printf("TCP connection to %s attempt %d failed: %v", address, attempt, err)
		time.Sleep(time.Second * time.Duration(attempt))
	}
	return fmt.Errorf("failed to connect to %s after 5 attempts", address)
}

// SendMessage sends a message to a peer over TCP.
func SendMessage(address string, msg *security.Message) error {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // For testing
		CurvePreferences:   []tls.CurveID{tls.X25519},
		MinVersion:         tls.VersionTLS13,
	}
	conn, err := tls.Dial("tcp", address, tlsConfig)
	if err != nil {
		return err
	}
	defer conn.Close()

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if _, err := conn.Write(append(data, '\n')); err != nil {
		return err
	}

	log.Printf("Sent message to %s: Type=%s", address, msg.Type)
	return nil
}
