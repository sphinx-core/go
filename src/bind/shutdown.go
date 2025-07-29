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

// go/src/bind/shutdown.go
package bind

import (
	"fmt"

	logger "github.com/sphinx-core/go/src/log"
)

// Shutdown gracefully shuts down all server components in the given NodeResources.
// Shutdown stops all servers and closes resources.
func Shutdown(resources []NodeResources) error {
	var errs []error
	for _, res := range resources {
		if res.P2PServer != nil {
			if err := res.P2PServer.CloseDB(); err != nil {
				logger.Errorf("Failed to close LevelDB for %s: %v", res.P2PServer.LocalNode().ID, err)
				errs = append(errs, err)
			}
		}
		if res.TCPServer != nil {
			if err := res.TCPServer.Stop(); err != nil {
				logger.Errorf("Failed to stop TCP server: %v", err)
				errs = append(errs, err)
			}
		}
		if res.HTTPServer != nil {
			if err := res.HTTPServer.Stop(); err != nil {
				logger.Errorf("Failed to stop HTTP server: %v", err)
				errs = append(errs, err)
			}
		}
		if res.WebSocketServer != nil {
			if err := res.WebSocketServer.Stop(); err != nil {
				logger.Errorf("Failed to stop WebSocket server: %v", err)
				errs = append(errs, err)
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("errors during shutdown: %v", errs)
	}
	return nil
}
