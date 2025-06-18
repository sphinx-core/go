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

// go/src/bind/p2p.go
package bind

import (
	"fmt"
	"sync"
	"time"

	logger "github.com/sphinx-core/go/src/log"
	"github.com/sphinx-core/go/src/p2p"
)

// startP2PServer starts a P2P server for the given node.
func startP2PServer(name string, server *p2p.Server, readyCh chan struct{}, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Infof("Starting P2P server for %s on %s", name, server.LocalNode().Address)
		startCh := make(chan error, 1)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Errorf("Panic in P2P server startup for %s: %v", name, r)
					startCh <- fmt.Errorf("panic: %v", r)
				}
			}()
			logger.Infof("Calling server.Start() for %s", name)
			err := server.Start()
			logger.Infof("server.Start() for %s returned with error: %v", name, err)
			startCh <- err
		}()
		select {
		case err := <-startCh:
			if err != nil {
				logger.Errorf("P2P server failed for %s: %v", name, err)
				return
			}
			logger.Infof("P2P server for %s started successfully", name)
			logger.Infof("Sending ready signal for P2P server %s", name)
			readyCh <- struct{}{}
		case <-time.After(2 * time.Second):
			logger.Warnf("P2P server for %s took too long to start, assuming ready", name)
			logger.Infof("Sending ready signal for P2P server %s", name)
			readyCh <- struct{}{}
		}
	}()
}
