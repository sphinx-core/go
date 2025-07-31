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
	"log"
	"net"
	"time"

	"github.com/sphinx-core/go/src/core"
	security "github.com/sphinx-core/go/src/handshake"
)

// NewServer creates a new RPC server instance.
func NewServer(messageCh chan *security.Message, blockchain *core.Blockchain) *Server {
	metrics := NewMetrics()
	server := &Server{
		messageCh:    messageCh,
		metrics:      metrics,
		blockchain:   blockchain,
		queryManager: NewQueryManager(),
		store:        NewKVStore(),
	}
	server.handler = NewJSONRPCHandler(server)
	server.StartGarbageCollection() // Start GC when server is created
	go server.handleMessages()      // Start processing messages
	return server
}

// handleMessages processes incoming messages from the message channel.
func (s *Server) handleMessages() {
	for msg := range s.messageCh {
		log.Printf("rpc.Server: Received message on messageCh: Type=%s, Data=%v, ChannelLen=%d", msg.Type, msg.Data, len(s.messageCh))
		if msg.Type == "rpc" {
			dataBytes, ok := msg.Data.([]byte)
			if !ok {
				log.Printf("rpc.Server: Invalid RPC data format: %v", msg.Data)
				continue
			}
			// Decode the RPC message to get the From field
			var rpcMsg Message
			if err := rpcMsg.Unmarshal(dataBytes); err != nil {
				log.Printf("rpc.Server: Failed to unmarshal RPC message: %v", err)
				continue
			}
			log.Printf("rpc.Server: Decoded RPC message: RPCType=%s, RPCID=%v, From=%s, Query=%v", rpcMsg.RPCType, rpcMsg.RPCID, rpcMsg.From.Address.String(), rpcMsg.Query)
			// Process the RPC request
			respData, err := s.HandleRequest(dataBytes)
			if err != nil {
				log.Printf("rpc.Server: Error handling RPC request: %v", err)
				continue
			}
			log.Printf("rpc.Server: Processed RPC request, response: %s", string(respData))
			// Send response back to the client
			if err := s.sendResponse(rpcMsg.From.Address.String(), respData); err != nil {
				log.Printf("rpc.Server: Failed to send response to %s: %v", rpcMsg.From.Address.String(), err)
				continue
			}
			log.Printf("rpc.Server: Sent response to %s: %s", rpcMsg.From.Address.String(), string(respData))
		} else {
			log.Printf("rpc.Server: Ignoring non-RPC message type: %s", msg.Type)
		}
	}
}

// sendResponse sends an RPC response to the specified address.
func (s *Server) sendResponse(address string, respData []byte) error {
	conn, err := net.Dial("udp", address)
	if err != nil {
		return err
	}
	defer conn.Close() // defer is safe here as it runs after the function returns
	secMsg := &security.Message{Type: "rpc", Data: respData}
	encodedData, err := secMsg.Encode()
	if err != nil {
		return err
	}
	if _, err := conn.Write(encodedData); err != nil {
		return err
	}
	return nil
}

// HandleRequest processes an incoming RPC request (JSON or binary).
func (s *Server) HandleRequest(data []byte) ([]byte, error) {
	log.Printf("rpc.Server: Handling request: %s", string(data))
	// Try decoding as security.Message
	secMsg, err := security.DecodeMessage(data)
	if err == nil && secMsg.Type == "rpc" {
		dataBytes, ok := secMsg.Data.([]byte)
		if !ok {
			log.Printf("rpc.Server: Invalid RPC data format in security.Message: %v", secMsg.Data)
			return s.handler.errorResponse(nil, ErrCodeInvalidRequest, "Invalid RPC data format")
		}
		var msg Message
		if err := msg.Unmarshal(dataBytes); err != nil {
			log.Printf("rpc.Server: Invalid RPC message format: %v", err)
			return s.handler.errorResponse(nil, ErrCodeInvalidRequest, "Invalid RPC message format")
		}
		log.Printf("rpc.Server: Decoded RPC message: RPCType=%s, RPCID=%v, Query=%v", msg.RPCType, msg.RPCID, msg.Query)
		// Check if the response is expected
		if !msg.Query && !s.queryManager.IsExpectedResponse(msg) {
			log.Printf("rpc.Server: Unexpected response: RPCID=%v", msg.RPCID)
			return s.handler.errorResponse(msg.RPCID, ErrCodeInvalidRequest, "Unexpected response")
		}
		respData, err := s.handler.ProcessRequest(dataBytes)
		if err != nil {
			log.Printf("rpc.Server: Error processing RPC request: %v", err)
			return respData, err
		}
		log.Printf("rpc.Server: Successfully processed RPC request, response: %s", string(respData))
		return respData, nil
	}

	// Fallback to direct JSON/binary processing
	log.Printf("rpc.Server: Attempting direct JSON/binary processing: %s", string(data))
	return s.handler.ProcessRequest(data)
}

// StartGarbageCollection starts a goroutine to periodically clean up expired queries and key-value entries.
func (s *Server) StartGarbageCollection() {
	go func() {
		ticker := time.NewTicker(time.Second * 5)
		defer ticker.Stop()
		for range ticker.C {
			s.queryManager.GC()
			s.store.GC()
		}
	}()
}
