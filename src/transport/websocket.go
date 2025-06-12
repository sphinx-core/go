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

// go/src/transport/websocket.go
package transport

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	types "github.com/sphinx-core/go/src/core/transaction"
	"github.com/sphinx-core/go/src/rpc"
	"github.com/sphinx-core/go/src/security"
)

// NewWebSocketServer creates a new WebSocket server.
func NewWebSocketServer(address string, messageCh chan *security.Message, tlsConfig *tls.Config, rpcServer *rpc.Server) *WebSocketServer {
	mux := http.NewServeMux()
	return &WebSocketServer{
		address: address,
		mux:     mux,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true }, // Allow all origins for testing
		},
		messageCh: messageCh,
		tlsConfig: tlsConfig,
		rpcServer: rpcServer,
		handshake: security.NewHandshake(tlsConfig),
	}
}

// Start runs the WebSocket server.
func (s *WebSocketServer) Start() error {
	s.mux.HandleFunc("/ws", s.handleWebSocket)
	server := &http.Server{
		Addr:      s.address,
		Handler:   s.mux,
		TLSConfig: s.tlsConfig,
	}
	log.Printf("WebSocket server listening on %s/ws", s.address)
	return server.ListenAndServeTLS("", "")
}

// handleWebSocket upgrades HTTP to WebSocket.
func (s *WebSocketServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.handshake.Metrics.Errors.WithLabelValues("websocket").Inc()
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			log.Printf("WebSocket read error: %v", err)
			break
		}
		var msg security.Message
		if err := json.Unmarshal(raw, &msg); err != nil {
			log.Printf("WebSocket decode error: %v", err)
			continue
		}
		s.messageCh <- &msg

		if msg.Type == "jsonrpc" {
			resp, err := s.rpcServer.HandleRequest([]byte(msg.Data.(string)))
			if err != nil {
				log.Printf("RPC handle error: %v", err)
				continue
			}
			if err := conn.WriteMessage(websocket.TextMessage, resp); err != nil {
				log.Printf("WebSocket write error: %v", err)
				break
			}
		}
	}
}

// ConnectWebSocket connects to a peer via WebSocket.
func ConnectWebSocket(address string, messageCh chan *security.Message) error {
	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			CurvePreferences:   []tls.CurveID{tls.X25519},
			MinVersion:         tls.VersionTLS13,
		},
	}

	// Map TCP ports to WebSocket ports
	wsPortMap := map[string]string{
		"127.0.0.1:30303": "127.0.0.1:8546", // Alice
		"127.0.0.1:30304": "127.0.0.1:8548", // Bob
		"127.0.0.1:30305": "127.0.0.1:8550", // Charlie
	}
	wsAddress, ok := wsPortMap[address]
	if !ok {
		wsAddress = address // Fallback to provided address
	}

	for attempt := 1; attempt <= 3; attempt++ {
		conn, _, err := dialer.Dial("wss://"+wsAddress+"/ws", nil)
		if err == nil {
			defer conn.Close()

			header := types.NewBlockHeader(1, []byte{}, big.NewInt(1), []byte{}, []byte{}, big.NewInt(1000000), big.NewInt(0), []byte{}, []byte{})
			body := types.NewBlockBody([]*types.Transaction{}, []byte{})
			block := types.NewBlock(header, body)
			msg := &security.Message{Type: "block", Data: block}
			data, err := json.Marshal(msg)
			if err != nil {
				log.Printf("WebSocket encode error for %s on attempt %d: %v", wsAddress, attempt, err)
				continue
			}
			if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
				log.Printf("WebSocket write error for %s on attempt %d: %v", wsAddress, attempt, err)
				continue
			}

			_, respData, err := conn.ReadMessage()
			if err != nil {
				log.Printf("WebSocket read response error for %s on attempt %d: %v", wsAddress, attempt, err)
				continue
			}
			var respMsg security.Message
			if err := json.Unmarshal(respData, &respMsg); err != nil {
				log.Printf("WebSocket decode response error for %s on attempt %d: %v", wsAddress, attempt, err)
				continue
			}
			messageCh <- &respMsg

			log.Printf("WebSocket connected to %s", wsAddress)
			return nil
		}
		log.Printf("WebSocket connection to %s attempt %d failed: %v", wsAddress, attempt, err)
		time.Sleep(time.Second * time.Duration(attempt))
	}
	return fmt.Errorf("failed to connect to %s after 3 attempts", wsAddress)
}
