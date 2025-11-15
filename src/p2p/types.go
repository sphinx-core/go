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
	"net"
	"sync"
	"time"

	"github.com/sphinx-core/go/src/consensus"
	"github.com/sphinx-core/go/src/core"
	sign "github.com/sphinx-core/go/src/core/sphincs/sign/backend"
	security "github.com/sphinx-core/go/src/handshake"
	"github.com/sphinx-core/go/src/network"
	"github.com/syndtr/goleveldb/leveldb"
)

type Server struct {
	localNode   *network.Node
	nodeManager *network.NodeManager
	seedNodes   []string
	udpConn     *net.UDPConn
	messageCh   chan *security.Message
	blockchain  *core.Blockchain
	peerManager *PeerManager
	mu          sync.RWMutex
	db          *leveldb.DB
	sphincsMgr  *sign.SphincsManager
	stopCh      chan struct{} // Channel to signal stop
	udpReadyCh  chan struct{} // Channel to signal UDP readiness
	dht         network.DHT   // Add DHT field
	consensus   *consensus.Consensus
}

func (s *Server) LocalNode() *network.Node {
	return s.localNode
}

func (s *Server) NodeManager() *network.NodeManager {
	return s.nodeManager
}

func (s *Server) PeerManager() *PeerManager {
	return s.peerManager
}

func (s *Server) SetSphincsMgr(mgr *sign.SphincsManager) {
	s.sphincsMgr = mgr
}

type Peer = network.Peer

type PeerManager struct {
	server      *Server
	peers       map[string]*network.Peer
	scores      map[string]int
	bans        map[string]time.Time
	maxPeers    int
	maxInbound  int
	maxOutbound int
	mu          sync.RWMutex
}
