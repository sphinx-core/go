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

package http

import (
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sphinx-core/go/src/core"
	types "github.com/sphinx-core/go/src/core/transaction"
	"github.com/sphinx-core/go/src/security"
)

// Server handles HTTP requests.
type Server struct {
	address    string
	router     *gin.Engine
	messageCh  chan *security.Message
	blockchain *core.Blockchain
}

// NewServer creates a new HTTP server.
func NewServer(address string, messageCh chan *security.Message) *Server {
	r := gin.Default()
	s := &Server{
		address:    address,
		router:     r,
		messageCh:  messageCh,
		blockchain: core.NewBlockchain(),
	}
	s.setupRoutes()
	return s
}

// setupRoutes defines HTTP endpoints.
func (s *Server) setupRoutes() {
	s.router.POST("/transaction", s.handleTransaction)
	s.router.GET("/block/:id", s.handleGetBlock)
	s.router.GET("/bestblockhash", s.handleGetBestBlockHash)
	s.router.GET("/blockcount", s.handleGetBlockCount)
	s.router.GET("/metrics", gin.WrapH(promhttp.Handler()))
}

// handleTransaction submits a transaction.
func (s *Server) handleTransaction(c *gin.Context) {
	var tx types.Transaction
	if err := c.ShouldBindJSON(&tx); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.blockchain.AddTransaction(tx); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.messageCh <- &security.Message{Type: "transaction", Data: tx}
	c.JSON(http.StatusOK, gin.H{"status": "Transaction submitted"})
}

// handleGetBlock retrieves a block by ID.
func (s *Server) handleGetBlock(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid block ID"})
		return
	}
	blocks := s.blockchain.GetBlocks()
	for _, block := range blocks {
		if block.Header.Block == id {
			c.JSON(http.StatusOK, block)
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "block not found"})
}

// handleGetBestBlockHash returns the active chain’s tip hash.
func (s *Server) handleGetBestBlockHash(c *gin.Context) {
	hash := s.blockchain.GetBestBlockHash()
	c.JSON(http.StatusOK, gin.H{"hash": fmt.Sprintf("%x", hash)})
}

// handleGetBlockCount returns the active chain height.
func (s *Server) handleGetBlockCount(c *gin.Context) {
	count := s.blockchain.GetBlockCount()
	c.JSON(http.StatusOK, gin.H{"count": count})
}

// Start runs the HTTP server.
func (s *Server) Start() error {
	go func() {
		r := gin.Default()
		r.GET("/metrics", gin.WrapH(promhttp.Handler()))
		if err := r.Run("0.0.0.0:9090"); err != nil {
			log.Printf("Metrics server failed: %v", err)
		}
	}()
	return s.router.Run(s.address)
}
