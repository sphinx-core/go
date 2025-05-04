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
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocketConnWrapper is a wrapper around *websocket.Conn that implements io.ReadWriteCloser.
type WebSocketConnWrapper struct {
	*websocket.Conn
}

// ClientCodecWebSocket is the client-side codec for handling WebSocket RPC communication.
type ClientCodecWebSocket struct {
	conn *websocket.Conn
}

// NewWebSocketConnWrapper creates a new WebSocketConnWrapper.
func NewWebSocketConnWrapper(conn *websocket.Conn) *WebSocketConnWrapper {
	return &WebSocketConnWrapper{Conn: conn}
}

// Read implements the io.Reader interface for WebSocketConnWrapper.
func (w *WebSocketConnWrapper) Read(p []byte) (n int, err error) {
	_, message, err := w.Conn.ReadMessage()
	if err != nil {
		return 0, err
	}
	copy(p, message)
	return len(message), nil
}

// Write implements the io.Writer interface for WebSocketConnWrapper.
func (w *WebSocketConnWrapper) Write(p []byte) (n int, err error) {
	err = w.Conn.WriteMessage(websocket.TextMessage, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close implements the io.Closer interface for WebSocketConnWrapper.
func (w *WebSocketConnWrapper) Close() error {
	return w.Conn.Close()
}

// NewClientCodecWebSocket creates a new ClientCodecWebSocket instance with custom headers.
func NewClientCodecWebSocket(serverURL string, client *http.Client, headers map[string]string) (*ClientCodecWebSocket, error) {
	// Create a WebSocket dialer
	dialer := websocket.Dialer{
		HandshakeTimeout: 45 * time.Second,
	}

	// Prepare HTTP headers
	reqHeader := http.Header{}
	for key, value := range headers {
		reqHeader.Set(key, value)
	}

	// Dial the WebSocket server with custom headers
	conn, _, err := dialer.Dial(serverURL, reqHeader)
	if err != nil {
		return nil, fmt.Errorf("failed to dial WebSocket: %w", err)
	}

	// Return a new ClientCodecWebSocket instance
	return &ClientCodecWebSocket{
		conn: conn,
	}, nil
}

// ReadResponseHeader reads the header of the RPC response.
func (c *ClientCodecWebSocket) ReadResponseHeader(resp *Response) error {
	var raw json.RawMessage
	if err := c.conn.ReadJSON(&raw); err != nil {
		return fmt.Errorf("failed to read response header: %w", err)
	}

	var serverResp serverResponse
	if err := json.Unmarshal(raw, &serverResp); err != nil {
		return fmt.Errorf("failed to unmarshal response header: %w", err)
	}

	// Unmarshal the Id field from json.RawMessage to uint64
	var id uint64
	if serverResp.Id != nil {
		if err := json.Unmarshal(*serverResp.Id, &id); err != nil {
			return fmt.Errorf("failed to unmarshal response ID: %w", err)
		}
	} else {
		return fmt.Errorf("response ID is nil")
	}

	resp.Seq = id
	if serverResp.Error != nil {
		if errMsg, ok := serverResp.Error.(string); ok {
			resp.Error = errMsg
		} else {
			resp.Error = fmt.Sprintf("invalid error format: %v", serverResp.Error)
		}
	}
	resp.ServiceMethod = "" // Set based on your logic if needed
	return nil
}

// ReadResponseBody reads the response body.
func (c *ClientCodecWebSocket) ReadResponseBody(result interface{}) error {
	var raw json.RawMessage
	if err := c.conn.ReadJSON(&raw); err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}
	return json.Unmarshal(raw, result)
}
