// security/message.go
package security

import (
	"encoding/json"
	"errors"

	"github.com/yourusername/myblockchain/core"
)

// Message represents a secure P2P or RPC message.
type Message struct {
	Type string      `json:"type"` // e.g., "transaction", "block", "jsonrpc"
	Data interface{} `json:"data"`
}

// ValidateMessage ensures the message is valid.
func (m *Message) ValidateMessage() error {
	if m.Type == "" {
		return errors.New("message type is empty")
	}
	switch m.Type {
	case "transaction":
		if _, ok := m.Data.(core.Transaction); !ok {
			return errors.New("invalid transaction data")
		}
	case "block":
		if _, ok := m.Data.(core.Block); !ok {
			return errors.New("invalid block data")
		}
	case "jsonrpc":
		if data, ok := m.Data.(map[string]interface{}); !ok || data["jsonrpc"] != "2.0" {
			return errors.New("invalid JSON-RPC data")
		}
	default:
		return errors.New("unknown message type")
	}
	return nil
}

// Encode serializes the message to JSON.
func (m *Message) Encode() ([]byte, error) {
	return json.Marshal(m)
}

// DecodeMessage deserializes a message from JSON.
func DecodeMessage(data []byte) (*Message, error) {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	if err := msg.ValidateMessage(); err != nil {
		return nil, err
	}
	return &msg, nil
}
