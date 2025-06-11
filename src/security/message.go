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

// go/src/security/message.go
package security

import (
	"encoding/json"
	"errors"
	"math/big"

	types "github.com/sphinx-core/go/src/core/transaction"
	"github.com/sphinx-core/go/src/network"
)

// Message represents a secure P2P or RPC message.
type Message struct {
	Type string      `json:"type"` // e.g., "transaction", "block", "jsonrpc", "ping", "pong", "peer_info"
	Data interface{} `json:"data"`
}

// ValidateMessage ensures the message is valid.
func (m *Message) ValidateMessage() error {
	if m.Type == "" {
		return errors.New("message type is empty")
	}
	switch m.Type {
	case "transaction":
		if tx, ok := m.Data.(*types.Transaction); ok {
			if tx.Sender == "" || tx.Receiver == "" || tx.Amount.Cmp(big.NewInt(0)) <= 0 {
				return errors.New("invalid transaction data")
			}
		} else {
			return errors.New("invalid transaction type")
		}
	case "block":
		if _, ok := m.Data.(types.Block); !ok {
			return errors.New("invalid block data")
		}
	case "jsonrpc":
		if data, ok := m.Data.(map[string]interface{}); !ok || data["jsonrpc"] != "2.0" {
			return errors.New("invalid JSON-RPC data")
		}
	case "ping", "pong":
		if _, ok := m.Data.(string); !ok {
			return errors.New("invalid ping/pong data: must be node ID string")
		}
	case "peer_info":
		if _, ok := m.Data.(network.PeerInfo); !ok {
			return errors.New("invalid peer_info data")
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
