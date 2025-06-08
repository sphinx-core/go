// p2p/discovery.go
package p2p

import (
	"log"

	"github.com/yourusername/myblockchain/transport"
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
