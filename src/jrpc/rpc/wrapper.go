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
	"net/http"

	"github.com/gorilla/websocket"
)

// WebSocketConnWrapper is a wrapper around *websocket.Conn that implements io.ReadWriteCloser.
type WebSocketConnWrapper struct {
	*websocket.Conn
}

// ClientCodecWebSocket is the client-side codec for handling WebSocket RPC communication.
type ClientCodecWebSocket struct {
	conn   *websocket.Conn
	client *http.Client
}

// NewWebSocketConnWrapper creates a new WebSocketConnWrapper.
func NewWebSocketConnWrapper(conn *websocket.Conn) *WebSocketConnWrapper {
	return &WebSocketConnWrapper{Conn: conn}
}

// ReadResponseHeader reads the header of the RPC response.
func (c *ClientCodecWebSocket) ReadResponseHeader(resp *Response) error {
	// Read the response header (just an example of parsing JSON, adjust as needed)
	return c.conn.ReadJSON(resp)
}

// ReadResponseBody reads the response body.
func (c *ClientCodecWebSocket) ReadResponseBody(result interface{}) error {
	// Read the response body (the actual result of the RPC call)
	return c.conn.ReadJSON(result)
}

// NewClientCodecWebSocket creates a new ClientCodecWebSocket instance.
func NewClientCodecWebSocket(serverURL string, client *http.Client) (*ClientCodecWebSocket, error) {
	// Dial the WebSocket server
	conn, _, err := websocket.DefaultDialer.Dial(serverURL, nil)
	if err != nil {
		return nil, err
	}

	// Return a new ClientCodecWebSocket instance
	return &ClientCodecWebSocket{
		conn:   conn,
		client: client,
	}, nil
}

// Read implements the io.Reader interface for WebSocketConnWrapper.
func (w *WebSocketConnWrapper) Read(p []byte) (n int, err error) {
	// Read from the WebSocket connection into a temporary message variable
	_, message, err := w.Conn.ReadMessage()
	if err != nil {
		return 0, err
	}

	// Copy the message content into the provided buffer p
	copy(p, message)
	return len(message), nil
}

// Write implements the io.Writer interface for WebSocketConnWrapper.
func (w *WebSocketConnWrapper) Write(p []byte) (n int, err error) {
	// Write to the WebSocket connection
	err = w.Conn.WriteMessage(websocket.TextMessage, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close implements the io.Closer interface for WebSocketConnWrapper.
func (w *WebSocketConnWrapper) Close() error {
	// Close the WebSocket connection
	return w.Conn.Close()
}
