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

package transport

import (
	"crypto/tls"
	"encoding/json"
	"log"
	"math/big"
	"net/http"

	"github.com/gorilla/websocket"
	types "github.com/sphinx-core/go/src/core/transaction"
	"github.com/sphinx-core/go/src/rpc"
	"github.com/sphinx-core/go/src/security"
)

// WebSocketServer handles WebSocket connections.
type WebSocketServer struct {
	address   string
	upgrader  websocket.Upgrader
	messageCh chan *security.Message
	tlsConfig *tls.Config
	rpcServer *rpc.Server
	handshake *security.Handshake
}

// NewWebSocketServer creates a new WebSocket server.
func NewWebSocketServer(address string, messageCh chan *security.Message, tlsConfig *tls.Config, rpcServer *rpc.Server) *WebSocketServer {
	return &WebSocketServer{
		address:   address,
		upgrader:  websocket.Upgrader{},
		messageCh: messageCh,
		tlsConfig: tlsConfig,
		rpcServer: rpcServer,
		handshake: security.NewHandshake(tlsConfig),
	}
}

// Start runs the WebSocket server.
func (s *WebSocketServer) Start() error {
	http.HandleFunc("/ws", s.handleWebSocket)
	server := &http.Server{
		Addr:      s.address,
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
		var raw []byte
		if err := conn.ReadJSON(&raw); err != nil {
			log.Printf("WebSocket read error: %v", err)
			break
		}
		msg, err := security.DecodeMessage(raw)
		if err != nil {
			log.Printf("WebSocket decode error: %v", err)
			continue
		}
		s.messageCh <- msg

		if msg.Type == "jsonrpc" {
			resp, err := s.rpcServer.HandleRequest([]byte(msg.Data.(string)))
			if err != nil {
				log.Printf("RPC handle error: %v", err)
				continue
			}
			if err := conn.WriteJSON(json.RawMessage(resp)); err != nil {
				log.Printf("WebSocket write error: %v", err)
			}
		}
	}
}

// ConnectWebSocket connects to a peer via WebSocket.
func ConnectWebSocket(address string, messageCh chan *security.Message) error {
	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // For testing
			CurvePreferences:   []tls.CurveID{tls.X25519},
			MinVersion:         tls.VersionTLS13,
		},
	}
	conn, _, err := dialer.Dial("wss://"+address+"/ws", nil)
	if err != nil {
		return err
	}
	defer conn.Close()

	header := types.NewBlockHeader(1, []byte{}, big.NewInt(1), []byte{}, []byte{}, big.NewInt(1000000), big.NewInt(0), []byte{}, []byte{})
	body := types.NewBlockBody([]*types.Transaction{}, []byte{})
	block := types.NewBlock(header, body)
	msg := &security.Message{Type: "block", Data: *block}
	return conn.WriteJSON(msg)
}
