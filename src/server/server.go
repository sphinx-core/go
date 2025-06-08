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

package server

import (
	"crypto/tls"

	"github.com/sphinx-core/go/src/http"
	"github.com/sphinx-core/go/src/security"
	"github.com/sphinx-core/go/src/transport"
)

// Server manages all protocol servers.
type Server struct {
	tcpServer  *transport.TCPServer
	wsServer   *transport.WebSocketServer
	httpServer *http.Server
}

// NewServer creates a new server.
func NewServer(tcpAddr, wsAddr, httpAddr string, tlsConfig *tls.Config) *Server {
	messageCh := make(chan *security.Message)
	return &Server{
		tcpServer:  transport.NewTCPServer(tcpAddr, messageCh, tlsConfig),
		wsServer:   transport.NewWebSocketServer(wsAddr, messageCh, tlsConfig),
		httpServer: http.NewServer(httpAddr, messageCh),
	}
}

// Start runs all servers.
func (s *Server) Start() error {
	go s.tcpServer.Start()
	go s.httpServer.Start()
	return s.wsServer.Start()
}
