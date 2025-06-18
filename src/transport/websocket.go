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
// It sets up the HTTP ServeMux, WebSocket upgrader with a permissive CheckOrigin,
// and stores the provided message channel and rpcServer for use in message handling.
func NewWebSocketServer(address string, messageCh chan *security.Message, rpcServer *rpc.Server) *WebSocketServer {
	mux := http.NewServeMux() // Create new HTTP request multiplexer
	return &WebSocketServer{
		address: address, // server listen address
		mux:     mux,     // HTTP request multiplexer
		upgrader: websocket.Upgrader{ // WebSocket upgrader config
			CheckOrigin: func(r *http.Request) bool { return true }, // allow all origins
		},
		messageCh: messageCh,               // channel for incoming secure messages
		rpcServer: rpcServer,               // RPC server for handling JSON-RPC requests
		handshake: security.NewHandshake(), // initialize handshake handler
	}
}

// Start begins listening for incoming HTTP requests and upgrades WebSocket connections.
// Registers "/ws" endpoint handler and starts HTTP server on the configured address.
func (s *WebSocketServer) Start() error {
	s.mux.HandleFunc("/ws", s.handleWebSocket) // register WebSocket handler at /ws path
	server := &http.Server{
		Addr:    s.address, // listen address
		Handler: s.mux,     // HTTP handler (mux)
	}
	log.Printf("WebSocket server listening on %s/ws", s.address) // log server start
	return server.ListenAndServe()                               // start HTTP server (blocking call)
}

// handleWebSocket upgrades HTTP connections to WebSocket, performs handshake,
// and then continuously reads, decodes, and processes messages from the connection.
func (s *WebSocketServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil) // upgrade HTTP to WebSocket connection
	if err != nil {
		s.handshake.Metrics.Errors.WithLabelValues("websocket").Inc() // increment error metric
		log.Printf("WebSocket upgrade error: %v", err)                // log error
		return
	}
	defer conn.Close() // ensure connection is closed when function returns

	// Wrap WebSocket connection to satisfy net.Conn interface for handshake
	wsConn := &websocketConn{conn: conn}
	enc, err := s.handshake.PerformHandshake(wsConn, "websocket", false) // perform secure handshake
	if err != nil {
		log.Printf("WebSocket handshake failed: %v", err) // log handshake failure
		return
	}

	for {
		_, raw, err := conn.ReadMessage() // read next message from WebSocket
		if err != nil {
			log.Printf("WebSocket read error: %v", err) // log read error and exit loop
			break
		}
		msg, err := security.DecodeSecureMessage(raw, enc) // decode encrypted message using established key
		if err != nil {
			log.Printf("WebSocket decode error: %v", err) // log decode error, continue reading next message
			continue
		}
		s.messageCh <- msg // send decoded message into the message channel

		if msg.Type == "jsonrpc" { // if message is JSON-RPC request
			resp, err := s.rpcServer.HandleRequest([]byte(msg.Data.(string))) // handle RPC request
			if err != nil {
				log.Printf("RPC handle error: %v", err) // log RPC handler error and continue
				continue
			}
			encryptedResp, err := security.SecureMessage(&security.Message{Type: "jsonrpc", Data: string(resp)}, enc) // encrypt RPC response
			if err != nil {
				log.Printf("WebSocket encode error: %v", err) // log encryption error and continue
				continue
			}
			if err := conn.WriteMessage(websocket.TextMessage, encryptedResp); err != nil { // send encrypted response
				log.Printf("WebSocket write error: %v", err) // log write error and break loop
				break
			}
		}
	}
}

// websocketConn wraps a *websocket.Conn to implement the net.Conn interface,
// enabling use of WebSocket connections in code expecting net.Conn.
type websocketConn struct {
	conn *websocket.Conn // underlying WebSocket connection
	buf  []byte          // buffer to hold leftover data from previous reads
}

// Read reads data into b, fulfilling net.Conn Read method.
// It uses an internal buffer if data remains from a previous read.
func (wc *websocketConn) Read(b []byte) (n int, err error) {
	if len(wc.buf) > 0 { // if leftover data in buffer
		n = copy(b, wc.buf) // copy buffered data into b
		wc.buf = wc.buf[n:] // remove copied bytes from buffer
		return n, nil       // return number of bytes read
	}
	_, data, err := wc.conn.ReadMessage() // read next WebSocket message
	if err != nil {
		return 0, err // return read error
	}
	n = copy(b, data)  // copy data into b
	if n < len(data) { // if not all data fit in b
		wc.buf = data[n:] // save remaining data to buffer
	}
	return n, nil // return number of bytes read
}

// Write writes data b as a WebSocket text message, fulfilling net.Conn Write method.
func (wc *websocketConn) Write(b []byte) (n int, err error) {
	return len(b), wc.conn.WriteMessage(websocket.TextMessage, b) // send b as text message, return length and error
}

// Close closes the underlying WebSocket connection.
func (wc *websocketConn) Close() error {
	return wc.conn.Close() // close connection
}

// LocalAddr returns nil as local address is not exposed via WebSocketConn.
func (wc *websocketConn) LocalAddr() net.Addr { return nil }

// RemoteAddr returns nil as remote address is not exposed via WebSocketConn.
func (wc *websocketConn) RemoteAddr() net.Addr { return nil }

// SetDeadline is a no-op returning nil to satisfy net.Conn interface.
func (wc *websocketConn) SetDeadline(t time.Time) error { return nil }

// SetReadDeadline is a no-op returning nil to satisfy net.Conn interface.
func (wc *websocketConn) SetReadDeadline(t time.Time) error { return nil }

// SetWriteDeadline is a no-op returning nil to satisfy net.Conn interface.
func (wc *websocketConn) SetWriteDeadline(t time.Time) error { return nil }

// ConnectWebSocket tries to establish a WebSocket connection to the specified address,
// performing handshake and sending a test message. It retries up to 3 times on failure.
func ConnectWebSocket(address string, messageCh chan *security.Message) error {
	dialer := websocket.Dialer{} // create WebSocket dialer

	// map of local addresses to corresponding WebSocket addresses (port mapping)
	wsPortMap := map[string]string{
		"127.0.0.1:30303": "127.0.0.1:8546",
		"127.0.0.1:30304": "127.0.0.1:8548",
		"127.0.0.1:30305": "127.0.0.1:8550",
	}

	wsAddress, ok := wsPortMap[address] // look up mapped WebSocket address
	if !ok {
		wsAddress = address // if no mapping found, use original address
	}

	// attempt connection up to 3 times
	for attempt := 1; attempt <= 3; attempt++ {
		conn, _, err := dialer.Dial("ws://"+wsAddress+"/ws", nil) // dial WebSocket server at /ws path
		if err == nil {
			defer conn.Close() // ensure connection close on function exit

			// Wrap connection for handshake
			wsConn := &websocketConn{conn: conn}
			handshake := security.NewHandshake()                              // create new handshake instance
			enc, err := handshake.PerformHandshake(wsConn, "websocket", true) // perform handshake with server
			if err != nil {
				log.Printf("WebSocket handshake failed for %s on attempt %d: %v", wsAddress, attempt, err) // log error
				continue                                                                                   // try next attempt
			}

			// Prepare example message of type "block" with empty struct as data
			msg := &security.Message{Type: "block", Data: struct{}{}}
			data, err := security.SecureMessage(msg, enc) // encrypt message using established key
			if err != nil {
				log.Printf("WebSocket encode error for %s on attempt %d: %v", wsAddress, attempt, err) // log encode error
				continue                                                                               // try next attempt
			}

			// Write encrypted message to WebSocket
			if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
				log.Printf("WebSocket write error for %s on attempt %d: %v", wsAddress, attempt, err) // log write error
				continue                                                                              // try next attempt
			}

			// Read response message from WebSocket
			_, respData, err := conn.ReadMessage()
			if err != nil {
				log.Printf("WebSocket read response error for %s on attempt %d: %v", wsAddress, attempt, err) // log read error
				continue                                                                                      // try next attempt
			}
			respMsg, err := security.DecodeSecureMessage(respData, enc) // decode encrypted response
			if err != nil {
				log.Printf("WebSocket decode response error for %s on attempt %d: %v", wsAddress, attempt, err) // log decode error
				continue                                                                                        // try next attempt
			}
			messageCh <- respMsg // send decoded response message to channel

			log.Printf("WebSocket connected to %s", wsAddress) // log successful connection
			return nil                                         // success
		}
		// log failed attempt with error
		log.Printf("WebSocket connection to %s attempt %d failed: %v", wsAddress, attempt, err)
		time.Sleep(time.Second * time.Duration(attempt)) // exponential backoff delay before retrying
	}
	// failed all attempts
	return fmt.Errorf("failed to connect to %s after 3 attempts", wsAddress)
}
