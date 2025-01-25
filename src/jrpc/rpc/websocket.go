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
	"log"
	"net/http"
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
				// Allow all origins for WebSocket connections
				return true
			},
		},
		clients: make(map[*websocket.Conn]PeerInfo),
	}
}

// HandleWebSocketUpgrade handles incoming HTTP requests and upgrades them to WebSocket connections.
// HandleWebSocketUpgrade handles incoming HTTP requests and upgrades them to WebSocket connections.
func (ws *WebSocketServer) HandleWebSocketUpgrade(w http.ResponseWriter, r *http.Request) {
	// Get the Base64-encoded custom header from the HTTP request (if present)
	encodedHeader := r.Header.Get("X-Client-Header")

	// If the custom header exists, decode it from Base64
	var decodedHeader string
	if encodedHeader != "" {
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
		decodedHeader = string(decodedData) // Store the decoded header
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
		Transport:  "ws",                       // Indicate WebSocket transport
		RemoteAddr: conn.RemoteAddr().String(), // Get the client's remote address
		Timestamp:  time.Now(),                 // Store the connection timestamp
		HeaderInfo: decodedHeader,              // Store the decoded header info
	}

	// Add the WebSocket connection to the client list
	ws.clients[conn] = peer

	// Serve the WebSocket connection with the RPC server
	go ws.serveWebSocketConnection(conn, peer)
}

// serveWebSocketConnection handles incoming WebSocket messages and processes RPC requests.
func (ws *WebSocketServer) serveWebSocketConnection(conn *websocket.Conn, peer PeerInfo) {
	defer func() {
		// Cleanup the connection when it is closed
		conn.Close()
		delete(ws.clients, conn)
		log.Printf("WebSocket connection closed: %s", conn.RemoteAddr())
	}()

	// Create a new RPC server codec for the WebSocket connection
	wsConn := NewWebSocketConnWrapper(conn)
	serverCodec := NewServerCodec(wsConn, peer)

	// Process incoming WebSocket messages as RPC requests
	for {
		// Read message from the WebSocket connection
		var msg serverRequest
		if err := conn.ReadJSON(&msg); err != nil {
			if websocket.IsCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				// Connection closed, exit the loop
				break
			}
			log.Printf("Error reading WebSocket message: %v", err)
			continue
		}

		// Handle RPC request by serving it via the codec
		if err := serverCodec.ReadRequestHeader(nil); err != nil {
			log.Printf("Error reading RPC request header: %v", err)
			continue
		}
		if err := serverCodec.ReadRequestBody(nil); err != nil {
			log.Printf("Error reading RPC request body: %v", err)
			continue
		}

		// Process and respond with the result
		// Make sure to send the response to the WebSocket connection
		var result interface{}
		if err := serverCodec.WriteResponse(nil, result); err != nil {
			log.Printf("Error writing RPC response: %v", err)
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
	// Close all active connections with a timeout
	for conn := range ws.clients {
		ws.CloseClientConnection(conn)
	}

	// Log and return shutdown success
	log.Println("WebSocket server shut down successfully.")
	return nil
}
