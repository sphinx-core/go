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
	"fmt"
	"log"
	"net"
	"time"

	"github.com/sphinx-core/go/src/rpc"
	"github.com/sphinx-core/go/src/security"
)

func NewTCPServer(address string, messageCh chan *security.Message, rpcServer *rpc.Server) *TCPServer {
	return &TCPServer{
		address:   address,
		messageCh: messageCh,
		rpcServer: rpcServer,
		handshake: security.NewHandshake(),
	}
}

func (s *TCPServer) Start() error {
	listener, err := net.Listen("tcp", s.address)
	if err != nil {
		log.Printf("Failed to bind TCP listener on %s: %v", s.address, err)
		return err
	}
	s.listener = listener
	log.Printf("TCP server listening on %s", s.address)

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

func (s *TCPServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Perform Kyber768 handshake (server is responder)
	ek, err := s.handshake.PerformHandshake(conn, "tcp", false)
	if err != nil {
		log.Printf("TCP handshake failed on %s: %v", s.address, err)
		return
	}

	reader := bufio.NewReader(conn)
	for {
		data, err := reader.ReadBytes('\n')
		if err != nil {
			log.Printf("TCP read error on %s: %v", s.address, err)
			return
		}

		msg, err := security.DecodeSecureMessage(data[:len(data)-1], ek)
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
			encryptedResp, err := security.SecureMessage(&security.Message{Type: "jsonrpc", Data: string(resp)}, ek)
			if err != nil {
				log.Printf("TCP encode response error on %s: %v", s.address, err)
				continue
			}
			if _, err := conn.Write(append(encryptedResp, '\n')); err != nil {
				log.Printf("TCP write error on %s: %v", s.address, err)
				return
			}
		}
	}
}

func ConnectTCP(address string, messageCh chan *security.Message) error {
	for attempt := 1; attempt <= 5; attempt++ {
		conn, err := net.Dial("tcp", address)
		if err == nil {
			defer conn.Close()

			// Perform Kyber768 handshake (client is initiator)
			handshake := security.NewHandshake()
			ek, err := handshake.PerformHandshake(conn, "tcp", true)
			if err != nil {
				log.Printf("TCP handshake failed for %s on attempt %d: %v", address, attempt, err)
				continue
			}

			// Send example message
			msg := &security.Message{Type: "ping", Data: "hello"}
			data, err := security.SecureMessage(msg, ek)
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
			respMsg, err := security.DecodeSecureMessage(respData[:len(respData)-1], ek)
			if err != nil {
				log.Printf("TCP decode response error for %s on attempt %d: %v", address, attempt, err)
				continue
			}
			messageCh <- respMsg

			log.Printf("TCP connected to %s", address)
			return nil
		}
		log.Printf("TCP connection to %s attempt %d failed: %v", address, attempt, err)
		time.Sleep(time.Second * time.Duration(attempt))
	}
	return fmt.Errorf("failed to connect to %s after 5 attempts", address)
}

func SendMessage(address string, msg *security.Message) error {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Perform Kyber768 handshake
	handshake := security.NewHandshake()
	ek, err := handshake.PerformHandshake(conn, "tcp", true)
	if err != nil {
		return err
	}

	data, err := security.SecureMessage(msg, ek)
	if err != nil {
		return err
	}
	if _, err := conn.Write(append(data, '\n')); err != nil {
		return err
	}

	log.Printf("Sent message to %s: Type=%s", address, msg.Type)
	return nil
}
