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
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	security "github.com/sphinx-core/go/src/handshake"
	"github.com/sphinx-core/go/src/rpc"
)

// NewWebSocketServer initializes and returns a new WebSocketServer struct.
func NewWebSocketServer(address string, messageCh chan *security.Message, rpcServer *rpc.Server) *WebSocketServer {
	mux := http.NewServeMux()
	return &WebSocketServer{
		address: address,
		mux:     mux,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
		messageCh: messageCh,
		rpcServer: rpcServer,
		handshake: security.NewHandshake(),
	}
}

// Start begins listening for WebSocket connections and signals readiness.
func (s *WebSocketServer) Start(readyCh chan struct{}) error {
	s.mux.HandleFunc("/ws", s.handleWebSocket)
	s.server = &http.Server{
		Addr:    s.address,
		Handler: s.mux,
	}
	log.Printf("WebSocket server listening on %s/ws", s.address)
	go func() {
		if readyCh != nil {
			readyCh <- struct{}{}
			log.Printf("Sent WebSocket ready signal for %s", s.address)
		}
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("WebSocket server error on %s: %v", s.address, err)
		}
	}()
	return nil
}

// Stop gracefully shuts down the WebSocket server.
func (s *WebSocketServer) Stop() error {
	if s.server == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown WebSocket server on %s: %v", s.address, err)
	}
	log.Printf("WebSocket server on %s stopped", s.address)
	return nil
}

// handleWebSocket upgrades HTTP connections to WebSocket, performs handshake,
// and processes messages.
func (s *WebSocketServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.handshake.Metrics.Errors.WithLabelValues("websocket").Inc()
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	wsConn := &websocketConn{conn: conn}
	enc, err := s.handshake.PerformHandshake(wsConn, "websocket", false)
	if err != nil {
		log.Printf("WebSocket handshake failed: %v", err)
		return
	}

	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			log.Printf("WebSocket read error: %v", err)
			break
		}
		msg, err := security.DecodeSecureMessage(raw, enc)
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
			encryptedResp, err := security.SecureMessage(&security.Message{Type: "jsonrpc", Data: string(resp)}, enc)
			if err != nil {
				log.Printf("WebSocket encode error: %v", err)
				continue
			}
			if err := conn.WriteMessage(websocket.TextMessage, encryptedResp); err != nil {
				log.Printf("WebSocket write error: %v", err)
				break
			}
		}
	}
}

// websocketConn wraps a *websocket.Conn to implement the net.Conn interface.
type websocketConn struct {
	conn *websocket.Conn
	buf  []byte
}

func (wc *websocketConn) Read(b []byte) (n int, err error) {
	if len(wc.buf) > 0 {
		n = copy(b, wc.buf)
		wc.buf = wc.buf[n:]
		return n, nil
	}
	_, data, err := wc.conn.ReadMessage()
	if err != nil {
		return 0, err
	}
	n = copy(b, data)
	if n < len(data) {
		wc.buf = data[n:]
	}
	return n, nil
}

func (wc *websocketConn) Write(b []byte) (n int, err error) {
	return len(b), wc.conn.WriteMessage(websocket.TextMessage, b)
}

func (wc *websocketConn) Close() error {
	return wc.conn.Close()
}

func (wc *websocketConn) LocalAddr() net.Addr                { return nil }
func (wc *websocketConn) RemoteAddr() net.Addr               { return nil }
func (wc *websocketConn) SetDeadline(t time.Time) error      { return nil }
func (wc *websocketConn) SetReadDeadline(t time.Time) error  { return nil }
func (wc *websocketConn) SetWriteDeadline(t time.Time) error { return nil }

// ConnectWebSocket tries to establish a WebSocket connection to the specified address.
func ConnectWebSocket(address string, messageCh chan *security.Message) error {
	dialer := websocket.Dialer{}
	wsPortMap := map[string]string{
		"127.0.0.1:30303": "127.0.0.1:8546",
		"127.0.0.1:30304": "127.0.0.1:8548",
		"127.0.0.1:30305": "127.0.0.1:8550",
	}
	wsAddress, ok := wsPortMap[address]
	if !ok {
		wsAddress = address
	}
	for attempt := 1; attempt <= 3; attempt++ {
		conn, _, err := dialer.Dial("ws://"+wsAddress+"/ws", nil)
		if err == nil {
			defer conn.Close()
			wsConn := &websocketConn{conn: conn}
			handshake := security.NewHandshake()
			enc, err := handshake.PerformHandshake(wsConn, "websocket", true)
			if err != nil {
				log.Printf("WebSocket handshake failed for %s on attempt %d: %v", wsAddress, attempt, err)
				continue
			}
			msg := &security.Message{Type: "block", Data: struct{}{}}
			data, err := security.SecureMessage(msg, enc)
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
			respMsg, err := security.DecodeSecureMessage(respData, enc)
			if err != nil {
				log.Printf("WebSocket decode response error for %s on attempt %d: %v", wsAddress, attempt, err)
				continue
			}
			messageCh <- respMsg
			log.Printf("WebSocket connected to %s", wsAddress)
			return nil
		}
		log.Printf("WebSocket connection to %s attempt %d failed: %v", wsAddress, attempt, err)
		time.Sleep(time.Second * time.Duration(attempt))
	}
	return fmt.Errorf("failed to connect to %s after 3 attempts", wsAddress)
}
