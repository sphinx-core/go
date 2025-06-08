package http

import (
	"github.com/gin-gonic/gin"
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

	lastTransaction *types.Transaction // store last transaction here
}
