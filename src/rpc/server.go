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

// go/src/rpc/server.go
package rpc

import (
	"github.com/sphinx-core/go/src/core"
	security "github.com/sphinx-core/go/src/handshake"
)

// NewServer creates a new RPC server instance.
func NewServer(messageCh chan *security.Message, blockchain *core.Blockchain) *Server {
	metrics := NewMetrics()
	server := &Server{
		messageCh:  messageCh,
		metrics:    metrics,
		blockchain: blockchain,
	}
	server.handler = NewJSONRPCHandler(server)
	return server
}

// HandleRequest processes an incoming JSON-RPC request and returns a response.
func (s *Server) HandleRequest(data []byte) ([]byte, error) {
	return s.handler.ProcessRequest(data)
}
