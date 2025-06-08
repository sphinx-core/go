// http/client.go
package http

import (
	"bytes"
	"net/http"

	"github.com/yourusername/myblockchain/core"
	"github.com/yourusername/myblockchain/security"
)

// SubmitTransaction sends a transaction via HTTP.
func SubmitTransaction(address string, tx core.Transaction) error {
	msg := &security.Message{Type: "transaction", Data: tx}
	data, err := msg.Encode()
	if err != nil {
		return err
	}
	resp, err := http.Post("http://"+address+"/transaction", "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
