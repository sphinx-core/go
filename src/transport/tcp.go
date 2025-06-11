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
	"crypto/tls"
	"log"
	"net"

	"github.com/sphinx-core/go/src/rpc"
	"github.com/sphinx-core/go/src/security"
)

// TCPServer handles TCP connections.
type TCPServer struct {
	address   string
	listener  net.Listener
	messageCh chan *security.Message
	tlsConfig *tls.Config
	rpcServer *rpc.Server
	handshake *security.Handshake
}

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
		return err
	}
	s.listener = listener
	log.Printf("TCP server listening on %s", s.address)

	for {
		conn, err := listener.Accept()
		if err != nil {
			s.handshake.Metrics.Errors.WithLabelValues("tcp").Inc()
			log.Printf("TCP accept error: %v", err)
			continue
		}
		go s.handleConnection(conn)
	}
}

// handleConnection processes incoming TCP connections.
func (s *TCPServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	if err := s.handshake.PerformHandshake(conn, "tcp"); err != nil {
		return
	}

	msg, err := security.DecodeMessage(readConn(conn))
	if err != nil {
		log.Printf("TCP decode error: %v", err)
		return
	}
	s.messageCh <- msg

	if msg.Type == "jsonrpc" {
		resp, err := s.rpcServer.HandleRequest([]byte(msg.Data.(string)))
		if err != nil {
			log.Printf("RPC handle error: %v", err)
			return
		}
		if _, err := conn.Write(resp); err != nil {
			log.Printf("TCP write error: %v", err)
		}
	}
}

// readConn reads data from a connection.
func readConn(conn net.Conn) []byte {
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	return buf[:n]
}

// ConnectTCP establishes a TLS-secured TCP connection to a peer.
func ConnectTCP(address string, messageCh chan *security.Message) error {
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

	// Perform handshake
	handshake := security.NewHandshake(tlsConfig)
	if err := handshake.PerformHandshake(conn, "tcp"); err != nil {
		return err
	}

	// Example message to test connection
	msg := &security.Message{Type: "ping", Data: "hello"}
	data, err := msg.Encode()
	if err != nil {
		return err
	}
	if _, err := conn.Write(data); err != nil {
		return err
	}

	// Read response
	respData := readConn(conn)
	respMsg, err := security.DecodeMessage(respData)
	if err != nil {
		log.Printf("TCP read error: %v", err)
		return err
	}
	messageCh <- respMsg

	log.Printf("TCP connected to %s", address)
	return nil
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

	data, err := msg.Encode()
	if err != nil {
		return err
	}
	if _, err := conn.Write(data); err != nil {
		return err
	}

	log.Printf("Sent message to %s: Type=%s", address, msg.Type)
	return nil
}
