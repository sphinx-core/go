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
	"time"

	security "github.com/sphinx-core/go/src/handshake"
	"github.com/sphinx-core/go/src/network"
	"github.com/sphinx-core/go/src/rpc"
)

// NewTCPServer creates and returns a new TCPServer instance
// with the given address, channel for messages, and rpc server.
func NewTCPServer(address string, messageCh chan *security.Message, rpcServer *rpc.Server, tcpReadyCh chan struct{}) *TCPServer {
	return &TCPServer{
		address:    address,
		messageCh:  messageCh,
		rpcServer:  rpcServer,
		handshake:  security.NewHandshake(),
		tcpReadyCh: tcpReadyCh,
	}
}

// Start starts the TCP server listening on s.address.
func (s *TCPServer) Start() error {
	listener, err := net.Listen("tcp", s.address)
	if err != nil {
		log.Printf("Failed to bind TCP listener on %s: %v", s.address, err)
		return fmt.Errorf("failed to bind TCP listener on %s: %v", s.address, err)
	}
	s.listener = listener
	log.Printf("TCP server successfully bound to %s", s.address)
	log.Printf("Sending TCP ready signal for %s", s.address)
	if s.tcpReadyCh != nil {
		s.tcpReadyCh <- struct{}{}
		log.Printf("Sent TCP ready signal for %s", s.address)
	} else {
		log.Printf("No tcpReadyCh provided for %s", s.address)
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			s.handshake.Metrics.Errors.WithLabelValues("tcp").Inc()
			log.Printf("TCP accept error on %s: %v", s.address, err)
			continue
		}
		log.Printf("Accepted new connection on %s from %s", s.address, conn.RemoteAddr().String())
		go s.handleConnection(conn)
	}
}

// handleConnection processes an individual TCP connection.
func (s *TCPServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	enc, err := s.handshake.PerformHandshake(conn, "tcp", false)
	if err != nil {
		log.Printf("TCP handshake failed on %s: %v", s.address, err)
		return
	}
	if enc == nil {
		log.Printf("TCP handshake returned nil encryption key on %s", s.address)
		return
	}

	reader := bufio.NewReader(conn)

	for {
		lengthBuf := make([]byte, 4)
		if _, err := io.ReadFull(reader, lengthBuf); err != nil {
			log.Printf("TCP read length error on %s: %v", s.address, err)
			return
		}
		length := binary.BigEndian.Uint32(lengthBuf)
		if length > 1024*1024 {
			log.Printf("TCP message too large on %s: %d bytes", s.address, length)
			return
		}

		data := make([]byte, length)
		if _, err := io.ReadFull(reader, data); err != nil {
			log.Printf("TCP read data error on %s: %v", s.address, err)
			return
		}
		log.Printf("Received raw data on %s, length: %d", s.address, len(data))

		msg, err := security.DecodeSecureMessage(data, enc)
		if err != nil {
			log.Printf("TCP decode error on %s: %v", s.address, err)
			continue
		}
		s.messageCh <- msg

		if msg.Type == "jsonrpc" {
			resp, err := s.rpcServer.HandleRequest([]byte(msg.Data.(string)))
			if err != nil {
				log.Printf("RPC handle error on %s: %v", s.address, err)
				continue
			}
			encryptedResp, err := security.SecureMessage(&security.Message{Type: "jsonrpc", Data: string(resp)}, enc)
			if err != nil {
				log.Printf("TCP encode response error on %s: %v", s.address, err)
				continue
			}
			lengthBuf = make([]byte, 4)
			binary.BigEndian.PutUint32(lengthBuf, uint32(len(encryptedResp)))
			if _, err := conn.Write(lengthBuf); err != nil {
				log.Printf("TCP write length error on %s: %v", s.address, err)
				return
			}
			if _, err := conn.Write(encryptedResp); err != nil {
				log.Printf("TCP write data error on %s: %v", s.address, err)
				return
			}
		}
	}
}

// ConnectTCP tries to establish a TCP connection to address, sending/receiving messages on messageCh.
func ConnectTCP(address string, messageCh chan *security.Message) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for attempt := 1; attempt <= 10; attempt++ {
		select {
		case <-ctx.Done():
			log.Printf("Overall timeout connecting to %s after %d attempts: %v", address, attempt, ctx.Err())
			return fmt.Errorf("timeout connecting to %s after %d attempts: %v", address, attempt, ctx.Err())
		default:
			conn, err := net.DialTimeout("tcp", address, 2*time.Second)
			if err != nil {
				sleepDuration := time.Second * time.Duration(1<<min(attempt-1, 4))
				log.Printf("TCP connection error: %s attempt %d failed: %v, retrying in %v", address, attempt, err, sleepDuration)
				time.Sleep(sleepDuration)
				continue
			}
			defer conn.Close()

			handshake := security.NewHandshake()
			enc, err := handshake.PerformHandshake(conn, "tcp", true)
			if err != nil {
				log.Printf("TCP handshake failed for %s on attempt %d: %v", address, attempt, err)
				continue
			}
			if enc == nil {
				log.Printf("TCP handshake returned nil encryption key for %s on attempt %d", address, attempt)
				continue
			}

			msg := &security.Message{Type: "ping", Data: "hello"}
			data, err := security.SecureMessage(msg, enc)
			if err != nil {
				log.Printf("TCP encode error for %s on attempt %d: %v", address, attempt, err)
				continue
			}
			lengthBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(lengthBuf, uint32(len(data)))
			if _, err := conn.Write(lengthBuf); err != nil {
				log.Printf("TCP write length error for %s on attempt %d: %v", address, attempt, err)
				continue
			}
			log.Printf("Sending message to %s, data length: %d", address, len(data))
			if _, err := conn.Write(data); err != nil {
				log.Printf("TCP write data error for %s on attempt %d: %v", address, attempt, err)
				continue
			}

			reader := bufio.NewReader(conn)
			lengthBuf = make([]byte, 4)
			if _, err := io.ReadFull(reader, lengthBuf); err != nil {
				log.Printf("TCP read length error on %s on attempt %d: %v", address, attempt, err)
				continue
			}
			length := binary.BigEndian.Uint32(lengthBuf)
			if length > 1024*1024 {
				log.Printf("TCP response too large on %s: %d bytes", address, length)
				continue
			}
			respData := make([]byte, length)
			if _, err := io.ReadFull(reader, respData); err != nil {
				log.Printf("TCP read data error on %s on attempt %d: %v", address, attempt, err)
				continue
			}
			log.Printf("Received response from %s, data length: %d", address, len(respData))
			respMsg, err := security.DecodeSecureMessage(respData, enc)
			if err != nil {
				log.Printf("TCP decode response error on %s on attempt %d: %v", address, attempt, err)
				continue
			}
			log.Printf("Attempting to send response to messageCh for %s, message type: %s", address, respMsg.Type)
			select {
			case messageCh <- respMsg:
				log.Printf("Sent response to messageCh for %s", address)
			case <-ctx.Done():
				log.Printf("Timeout sending to messageCh for %s: %v", address, ctx.Err())
				return fmt.Errorf("timeout sending to messageCh for %s: %v", address, ctx.Err())
			}

			log.Printf("TCP connected to %s", address)
			return nil
		}
	}
	log.Printf("Failed to connect to %s after 10 attempts", address)
	return fmt.Errorf("failed to connect to %s after 10 attempts", address)
}

// SendMessage sends a single secure message to the given TCP address.
func SendMessage(address string, msg *security.Message) error {
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	handshake := security.NewHandshake()
	enc, err := handshake.PerformHandshake(conn, "tcp", true)
	if err != nil {
		return err
	}
	if enc == nil {
		return fmt.Errorf("handshake returned nil encryption key for %s", address)
	}

	data, err := security.SecureMessage(msg, enc)
	if err != nil {
		return err
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

	log.Printf("Sent message to %s: Type=%s", address, msg.Type)
	return nil
}

// DisconnectNode closes the connection to a node.
func DisconnectNode(node *network.Node) error {
	addr, err := NodeToAddress(node)
	if err != nil {
		return fmt.Errorf("invalid node address: %v", err)
	}
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to dial %s: %v", addr, err)
	}
	err = conn.Close()
	if err != nil {
		return fmt.Errorf("failed to close connection to %s: %v", addr, err)
	}
	log.Printf("Disconnected from node %s at %s", node.ID, addr)
	return nil
}

// min is a helper to cap exponential backoff
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
