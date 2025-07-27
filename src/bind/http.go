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

// go/src/bind/http.go
package bind

import (
	"sync"
	"time"

	"github.com/sphinx-core/go/src/core"
	security "github.com/sphinx-core/go/src/handshake"
	"github.com/sphinx-core/go/src/http"
	logger "github.com/sphinx-core/go/src/log"
)

// startHTTPServer starts an HTTP server for the given node.
func startHTTPServer(name, port string, messageCh chan *security.Message, blockchain *core.Blockchain, readyCh chan struct{}, wg *sync.WaitGroup) {
	httpServer := http.NewServer(port, messageCh, blockchain, readyCh)
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Infof("Starting HTTP server for %s on %s", name, port)
		startCh := make(chan error, 1)
		go func() {
			if err := httpServer.Start(); err != nil {
				startCh <- err
			} else {
				startCh <- nil
			}
		}()
		select {
		case err := <-startCh:
			if err != nil {
				logger.Errorf("HTTP server failed for %s: %v", name, err)
				return
			}
		case <-time.After(2 * time.Second):
			logger.Infof("HTTP server for %s successfully started", name)
			logger.Infof("Sending ready signal for HTTP server %s", name)
			readyCh <- struct{}{}
		}
	}()
}
