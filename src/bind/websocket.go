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
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// go/src/bind/websocket.go
package bind

import (
	"sync"

	security "github.com/sphinx-core/go/src/handshake"
	logger "github.com/sphinx-core/go/src/log"
	"github.com/sphinx-core/go/src/rpc"
	"github.com/sphinx-core/go/src/transport"
)

// startWebSocketServer starts a WebSocket server for the given node.
func startWebSocketServer(name, port string, messageCh chan *security.Message, rpcServer *rpc.Server, readyCh chan struct{}, wg *sync.WaitGroup) {
	wsServer := transport.NewWebSocketServer(port, messageCh, rpcServer)
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Infof("Starting WebSocket server for %s on %s", name, port)
		if err := wsServer.Start(readyCh); err != nil {
			logger.Errorf("WebSocket server failed for %s: %v", name, err)
			return
		}
		logger.Infof("WebSocket server for %s successfully started", name)
	}()
}
