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

package p2p

import (
	"log"

	"github.com/sphinx-core/go/src/transport"
)

// DiscoverPeers connects to seed nodes and discovers peers.
func (s *Server) DiscoverPeers() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, seedAddr := range s.seedNodes {
		if seedAddr == s.address {
			continue
		}
		if _, exists := s.peers[seedAddr]; exists {
			continue
		}

		if err := transport.ConnectTCP(seedAddr, s.messageCh); err != nil {
			log.Printf("TCP connection to %s failed: %v", seedAddr, err)
			if err := transport.ConnectWebSocket(seedAddr, s.messageCh); err != nil {
				log.Printf("WebSocket connection to %s failed: %v", seedAddr, err)
				continue
			}
		}

		s.peers[seedAddr] = &Peer{Address: seedAddr}
		log.Printf("Discovered peer: %s", seedAddr)
	}
	return nil
}
