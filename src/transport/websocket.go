// transport/websocket.go
package transport

import (
	"crypto/tls"
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/websocket"
	"github.com/yourusername/myblockchain/core"
	"github.com/yourusername/myblockchain/rpc"
	"github.com/yourusername/myblockchain/security"
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
func NewWebSocketServer(address string, messageCh chan *security.Message, tlsConfig *tls.Config) *WebSocketServer {
	return &WebSocketServer{
		address:   address,
		upgrader:  websocket.Upgrader{},
		messageCh: messageCh,
		tlsConfig: tlsConfig,
		rpcServer: rpc.NewServer(messageCh),
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
			CurvePreferences:   []tls.CurveID{tls.X25519Kyber768Draft00, tls.X25519},
			MinVersion:         tls.VersionTLS13,
		},
	}
	conn, _, err := dialer.Dial("wss://"+address+"/ws", nil)
	if err != nil {
		return err
	}
	defer conn.Close()

	msg := &security.Message{Type: "block", Data: core.Block{ID: 1, Transactions: []core.Transaction{}}}
	return conn.WriteJSON(msg)
}
