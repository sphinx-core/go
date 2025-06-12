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
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/sphinx-core/go/src/rpc"
	"github.com/sphinx-core/go/src/security"
)

// NewTCPServer creates and returns a new TCPServer instance
// with the given address, channel for messages, and rpc server.
func NewTCPServer(address string, messageCh chan *security.Message, rpcServer *rpc.Server) *TCPServer {
	return &TCPServer{
		address:   address,                 // Server listening address (host:port)
		messageCh: messageCh,               // Channel to send decoded messages to
		rpcServer: rpcServer,               // RPC server for handling jsonrpc messages
		handshake: security.NewHandshake(), // New handshake instance for secure communication
	}
}

// Start starts the TCP server listening on s.address.
func (s *TCPServer) Start() error {
	// Listen on TCP network address s.address
	listener, err := net.Listen("tcp", s.address)
	if err != nil {
		// Log and return error if binding fails
		log.Printf("Failed to bind TCP listener on %s: %v", s.address, err)
		return err
	}
	s.listener = listener // Save listener for later use
	log.Printf("TCP server listening on %s", s.address)

	// Accept incoming connections indefinitely
	for {
		conn, err := listener.Accept() // Accept new TCP connection
		if err != nil {
			// Increment handshake error metric for TCP errors
			s.handshake.Metrics.Errors.WithLabelValues("tcp").Inc()
			log.Printf("TCP accept error on %s: %v", s.address, err)
			continue // On error, continue accepting next connections
		}
		// Handle each connection concurrently
		go s.handleConnection(conn)
	}
}

// handleConnection processes an individual TCP connection.
func (s *TCPServer) handleConnection(conn net.Conn) {
	defer conn.Close() // Ensure connection closes on function return

	// Perform KEM handshake (server is responder, so 'false' for initiator)
	enc, err := s.handshake.PerformHandshake(conn, "tcp", false)
	if err != nil {
		// Log handshake failure and exit connection handling
		log.Printf("TCP handshake failed on %s: %v", s.address, err)
		return
	}
	if enc == nil {
		// Log error if encryption key is nil (unexpected)
		log.Printf("TCP handshake returned nil encryption key on %s", s.address)
		return
	}

	reader := bufio.NewReader(conn) // Buffered reader for connection

	for {
		// Read 4 bytes from connection representing message length prefix
		lengthBuf := make([]byte, 4)
		if _, err := io.ReadFull(reader, lengthBuf); err != nil {
			// Log error and close connection on read failure
			log.Printf("TCP read length error on %s: %v", s.address, err)
			return
		}
		// Convert 4-byte length prefix from big endian to uint32
		length := binary.BigEndian.Uint32(lengthBuf)
		// Reject messages larger than 1MB for safety
		if length > 1024*1024 {
			log.Printf("TCP message too large on %s: %d bytes", s.address, length)
			return
		}

		// Allocate buffer for message data of specified length
		data := make([]byte, length)
		// Read full message data from connection
		if _, err := io.ReadFull(reader, data); err != nil {
			log.Printf("TCP read data error on %s: %v", s.address, err)
			return
		}
		log.Printf("Received raw data on %s, length: %d", s.address, len(data))

		// Decode and decrypt secure message using encryption key
		msg, err := security.DecodeSecureMessage(data, enc)
		if err != nil {
			// Log decode errors but continue listening for next messages
			log.Printf("TCP decode error on %s: %v", s.address, err)
			continue
		}
		// Send decoded message to the message channel
		s.messageCh <- msg

		// If message is JSON-RPC request, handle via rpcServer
		if msg.Type == "jsonrpc" {
			// Handle JSON-RPC request and get response bytes
			resp, err := s.rpcServer.HandleRequest([]byte(msg.Data.(string)))
			if err != nil {
				log.Printf("RPC handle error on %s: %v", s.address, err)
				continue
			}
			// Securely encode response message with encryption key
			encryptedResp, err := security.SecureMessage(&security.Message{Type: "jsonrpc", Data: string(resp)}, enc)
			if err != nil {
				log.Printf("TCP encode response error on %s: %v", s.address, err)
				continue
			}
			// Prepare 4-byte big endian length prefix for response
			lengthBuf = make([]byte, 4)
			binary.BigEndian.PutUint32(lengthBuf, uint32(len(encryptedResp)))
			// Write length prefix to connection
			if _, err := conn.Write(lengthBuf); err != nil {
				log.Printf("TCP write length error on %s: %v", s.address, err)
				return
			}
			// Write encrypted response data to connection
			if _, err := conn.Write(encryptedResp); err != nil {
				log.Printf("TCP write data error on %s: %v", s.address, err)
				return
			}
		}
	}
}

// ConnectTCP tries to establish a TCP connection to address, sending/receiving messages on messageCh.
func ConnectTCP(address string, messageCh chan *security.Message) error {
	// Try up to 5 attempts to connect
	for attempt := 1; attempt <= 5; attempt++ {
		conn, err := net.Dial("tcp", address) // Dial TCP connection
		if err != nil {
			log.Printf("TCP connection error: %s attempt %d failed: %v", address, attempt, err)
			// Sleep before retrying with increasing backoff
			time.Sleep(time.Second * time.Duration(attempt))
			continue
		}
		defer conn.Close() // Close connection on function exit

		// Create new handshake for client initiator (true)
		handshake := security.NewHandshake()
		enc, err := handshake.PerformHandshake(conn, "tcp", true)
		if err != nil {
			log.Printf("TCP handshake failed for %s on attempt %d: %v", address, err)
			continue
		}
		if enc == nil {
			log.Printf("TCP handshake returned nil encryption key for %s on attempt %d", address, attempt)
			continue
		}

		// Prepare a "ping" test message to verify connection
		msg := &security.Message{Type: "ping", Data: "hello"}
		// Securely encode the message with the encryption key
		data, err := security.SecureMessage(msg, enc)
		if err != nil {
			log.Printf("TCP encode error for %s on attempt %d: %v", address, attempt, err)
			continue
		}
		// Write 4-byte length prefix for the message data
		lengthBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lengthBuf, uint32(len(data)))
		if _, err := conn.Write(lengthBuf); err != nil {
			log.Printf("TCP write length error for %s on attempt %d: %v", address, attempt, err)
			continue
		}
		log.Printf("Sending message to %s, data length: %d", address, len(data))
		// Write the actual message data
		if _, err := conn.Write(data); err != nil {
			log.Printf("TCP write data error for %s on attempt %d: %v", address, attempt, err)
			continue
		}

		// Read response length prefix from connection
		reader := bufio.NewReader(conn)
		lengthBuf = make([]byte, 4)
		if _, err := io.ReadFull(reader, lengthBuf); err != nil {
			log.Printf("TCP read length error on %s on attempt %d: %v", address, attempt, err)
			continue
		}
		length := binary.BigEndian.Uint32(lengthBuf)
		// Reject response if too large (over 1MB)
		if length > 1024*1024 {
			log.Printf("TCP response too large on %s: %d bytes", address, length)
			continue
		}
		// Read full response data
		respData := make([]byte, length)
		if _, err := io.ReadFull(reader, respData); err != nil {
			log.Printf("TCP read data error on %s on attempt %d: %v", address, attempt, err)
			continue
		}
		log.Printf("Received response from %s, data length: %d", address, len(respData))
		// Decode and decrypt response message
		respMsg, err := security.DecodeSecureMessage(respData, enc)
		if err != nil {
			log.Printf("TCP decode response error on %s on attempt %d: %v", address, attempt, err)
			continue
		}
		// Send decoded response message to channel
		messageCh <- respMsg

		log.Printf("TCP connected to %s", address)
		return nil // Successful connection and response
	}
	// Return error if all attempts fail
	return fmt.Errorf("failed to connect to %s after 5 attempts", address)
}

// SendMessage sends a single secure message to the given TCP address.
func SendMessage(address string, msg *security.Message) error {
	// Dial TCP connection to the address
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return err // Return dialing error
	}
	defer conn.Close() // Ensure connection closes on function exit

	// Perform handshake as client initiator
	handshake := security.NewHandshake()
	enc, err := handshake.PerformHandshake(conn, "tcp", true)
	if err != nil {
		return err
	}
	if enc == nil {
		return fmt.Errorf("handshake returned nil encryption key for %s", address)
	}

	// Securely encode the message with encryption key
	data, err := security.SecureMessage(msg, enc)
	if err != nil {
		return err
	}
	// Write 4-byte length prefix before actual message
	lengthBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBuf, uint32(len(data)))
	if _, err := conn.Write(lengthBuf); err != nil {
		return fmt.Errorf("failed to write length to %s: %v", address, err)
	}
	log.Printf("Sending message to %s, data length: %d", address, len(data))
	// Write actual encrypted message data
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("failed to write data to %s: %v", address, err)
	}

	log.Printf("Sent message to %s: Type=%s", address, msg.Type)
	return nil
}
