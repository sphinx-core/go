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

// go/src/p2p/types.go
package p2p

import (
	"sync"
	"time"

	"github.com/sphinx-core/go/src/core"
	security "github.com/sphinx-core/go/src/handshake"
	"github.com/sphinx-core/go/src/network"
)

// Server represents a P2P server.
type Server struct {
	localNode   *network.Node
	nodeManager *network.NodeManager
	peerManager *PeerManager
	seedNodes   []string
	messageCh   chan *security.Message
	blockchain  *core.Blockchain
	mu          sync.Mutex
}

// LocalNode returns the server's local node.
func (s *Server) LocalNode() *network.Node {
	return s.localNode
}

// NodeManager returns the server's node manager.
func (s *Server) NodeManager() *network.NodeManager {
	return s.nodeManager
}

// PeerManager returns the server's peer manager.
func (s *Server) PeerManager() *PeerManager {
	return s.peerManager
}

// Peer is an alias for network.Peer to centralize peer management.
type Peer = network.Peer

// PeerManager handles peer lifecycle and communication.
type PeerManager struct {
	server      *Server
	peers       map[string]*network.Peer // Map of peer ID to peer
	scores      map[string]int           // Peer scores based on behavior
	bans        map[string]time.Time     // Banned peers with expiry
	maxPeers    int                      // Maximum number of peers
	maxInbound  int                      // Maximum inbound connections
	maxOutbound int                      // Maximum outbound connections
	mu          sync.RWMutex             // Mutex for thread-safe access
}
