// MIT License
//
// Copyright (c) 2024 sphinx-core
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
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,q
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package rpc

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/rpc"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocketServer defines the structure for the WebSocket server.
type WebSocketServer struct {
	upgrader websocket.Upgrader           // WebSocket upgrader for upgrading HTTP to WebSocket
	clients  map[*websocket.Conn]PeerInfo // Connected WebSocket clients and their PeerInfo
}

// NewWebSocketServer creates a new WebSocket server instance.
func NewWebSocketServer() *WebSocketServer {
	return &WebSocketServer{
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
		clients: make(map[*websocket.Conn]PeerInfo),
	}
}

// HandleWebSocketUpgrade handles incoming HTTP requests and upgrades them to WebSocket connections.
func (ws *WebSocketServer) HandleWebSocketUpgrade(w http.ResponseWriter, r *http.Request) {
	// Get the Base64-encoded custom header from the HTTP request (if present)
	encodedHeader := r.Header.Get("X-Client-Header")

	// If the custom header exists, validate and decode it
	var decodedHeader string
	if encodedHeader != "" {
		// Validate that the header contains only valid Base64 characters
		if !isValidBase64(encodedHeader) {
			log.Printf("Invalid Base64 header: %s", encodedHeader)
			http.Error(w, "Invalid Base64 header", http.StatusBadRequest)
			return
		}

		// Ensure proper padding before decoding
		if len(encodedHeader)%4 != 0 {
			encodedHeader += strings.Repeat("=", 4-len(encodedHeader)%4)
		}

		// Decode the Base64 header
		decodedData, err := base64.StdEncoding.DecodeString(encodedHeader)
		if err != nil {
			log.Printf("Error decoding Base64 header: %v", err)
			http.Error(w, "Invalid Base64 header", http.StatusBadRequest)
			return
		}
		decodedHeader = string(decodedData)
		log.Printf("Decoded client header: %s", decodedHeader)
	}

	// Upgrade HTTP connection to WebSocket
	conn, err := ws.upgrader.Upgrade(w, r, nil)
	if err != nil {
		http.Error(w, "Failed to upgrade to WebSocket: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Log the new WebSocket connection with the decoded header info
	log.Printf("New WebSocket connection: %s, Client header: %s", conn.RemoteAddr(), decodedHeader)

	// Populate the PeerInfo struct for the new connection
	peer := PeerInfo{
		Transport:  "ws",
		RemoteAddr: conn.RemoteAddr().String(),
		Timestamp:  time.Now(),
		HeaderInfo: decodedHeader,
	}

	// Add the WebSocket connection to the client list
	ws.clients[conn] = peer

	// Serve the WebSocket connection with the RPC server
	go ws.serveWebSocketConnection(conn, peer)
}

// isValidBase64 checks if the input string contains only valid Base64 characters.
func isValidBase64(s string) bool {
	for _, r := range s {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '+' || r == '/' || r == '=') {
			return false
		}
	}
	return true
}

// serveWebSocketConnection handles incoming WebSocket messages and processes RPC requests.
func (ws *WebSocketServer) serveWebSocketConnection(conn *websocket.Conn, peer PeerInfo) {
	defer func() {
		conn.Close()
		delete(ws.clients, conn)
		log.Printf("WebSocket connection closed: %s", conn.RemoteAddr())
	}()

	// Create a new RPC server codec for the WebSocket connection
	wsConn := NewWebSocketConnWrapper(conn)
	serverCodec := NewServerCodec(wsConn, peer)

	// Process incoming WebSocket messages as RPC requests
	for {
		// Read the RPC request header
		req := &rpc.Request{}
		if err := serverCodec.ReadRequestHeader(req); err != nil {
			if websocket.IsCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				break
			}
			log.Printf("Error reading RPC request header: %v", err)
			continue
		}

		// Read the request body
		var args interface{}
		if err := serverCodec.ReadRequestBody(&args); err != nil {
			log.Printf("Error reading RPC request body: %v", err)
			continue
		}

		// Simulate processing the request
		resp := &rpc.Response{
			Seq:           req.Seq,
			ServiceMethod: req.ServiceMethod,
		}
		result := "Processed: " + fmt.Sprintf("%v", args)

		// Write the response
		if err := serverCodec.WriteResponse(resp, result); err != nil {
			log.Printf("Error writing RPC response: %v", err)
			continue
		}
	}
}

// CloseClientConnection closes the WebSocket connection for a specific client.
func (ws *WebSocketServer) CloseClientConnection(conn *websocket.Conn) {
	conn.Close()
	delete(ws.clients, conn)
}

// Shutdown gracefully shuts down the WebSocket server.
func (ws *WebSocketServer) Shutdown(timeout time.Duration) error {
	for conn := range ws.clients {
		ws.CloseClientConnection(conn)
	}
	log.Println("WebSocket server shut down successfully.")
	return nil
}
