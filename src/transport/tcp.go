// transport/tcp.go
package transport

import (
	"crypto/tls"
	"log"
	"net"

	"github.com/yourusername/myblockchain/rpc"
	"github.com/yourusername/myblockchain/security"
)

// TCPServer handles TCP connections.
type TCPServer struct {
	address   string
	listener  net.Listener
	messageCh chan *security.Message
	tlsConfig *tls.Config
	rpcServer *rpc.Server
	handshake *security.Handshake
}

// NewTCPServer creates a new TCP server.
func NewTCPServer(address string, messageCh chan *security.Message, tlsConfig *tls.Config) *TCPServer {
	return &TCPServer{
		address:   address,
		messageCh: messageCh,
		tlsConfig: tlsConfig,
		rpcServer: rpc.NewServer(messageCh),
		handshake: security.NewHandshake(tlsConfig),
	}
}

// Start runs the TCP server.
func (s *TCPServer) Start() error {
	listener, err := tls.Listen("tcp", s.address, s.tlsConfig)
	if err != nil {
		return err
	}
	s.listener = listener
	log.Printf("TCP server listening on %s", s.address)

	for {
		conn, err := listener.Accept()
		if err != nil {
			s.handshake.Metrics.Errors.WithLabelValues("tcp").Inc()
			log.Printf("TCP accept error: %v", err)
			continue
		}
		go s.handleConnection(conn)
	}
}

// handleConnection processes incoming TCP connections.
func (s *TCPServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	if err := s.handshake.PerformHandshake(conn, "tcp"); err != nil {
		return
	}

	msg, err := security.DecodeMessage(readConn(conn))
	if err != nil {
		log.Printf("TCP decode error: %v", err)
		return
	}
	s.messageCh <- msg

	if msg.Type == "jsonrpc" {
		resp, err := s.rpcServer.HandleRequest([]byte(msg.Data.(string)))
		if err != nil {
			log.Printf("RPC handle error: %v", err)
			return
		}
		if _, err := conn.Write(resp); err != nil {
			log.Printf("TCP write error: %v", err)
		}
	}
}

// readConn reads data from a connection.
func readConn(conn net.Conn) []byte {
	buf := make([]byte, 4096) // Supports larger PQC messages
	n, _ := conn.Read(buf)
	return buf[:n]
}
