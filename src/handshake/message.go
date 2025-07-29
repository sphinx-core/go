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

// go/src/handshake/message.go
package security

import (
	"encoding/json"
	"errors"
	"math/big"

	types "github.com/sphinx-core/go/src/core/transaction"
	"github.com/sphinx-core/go/src/network"
)

// ValidateMessage ensures the message conforms to expected structure and type rules.
func (m *Message) ValidateMessage() error {
	// Check if the message type is not empty
	if m.Type == "" {
		return errors.New("message type is empty")
	}

	// Handle validation logic based on the message type
	switch m.Type {
	case "transaction":
		// Type assertion to check if Data is of *Transaction type
		if tx, ok := m.Data.(*types.Transaction); ok {
			// Validate that sender and receiver are set and amount is greater than 0
			if tx.Sender == "" || tx.Receiver == "" || tx.Amount.Cmp(big.NewInt(0)) <= 0 {
				return errors.New("invalid transaction data")
			}
		} else {
			// If type assertion fails, return error
			return errors.New("invalid transaction type")
		}
	case "block":
		// Check if Data is of type Block
		if _, ok := m.Data.(types.Block); !ok {
			return errors.New("invalid block data")
		}
	case "jsonrpc":
		// Check if Data is a map and contains correct JSON-RPC version
		if data, ok := m.Data.(map[string]interface{}); !ok || data["jsonrpc"] != "2.0" {
			return errors.New("invalid JSON-RPC data")
		}
	case "ping", "pong":
		// Validate that Data is a string (node ID)
		if _, ok := m.Data.(string); !ok {
			return errors.New("invalid ping/pong data: must be node ID string")
		}
	case "peer_info":
		// Validate that Data is of type PeerInfo
		if _, ok := m.Data.(network.PeerInfo); !ok {
			return errors.New("invalid peer_info data")
		}
	case "version":
		// Validate that Data is a map with required fields
		if data, ok := m.Data.(map[string]interface{}); ok {
			if _, ok := data["version"].(string); !ok {
				return errors.New("invalid version data: missing or invalid version")
			}
			if _, ok := data["node_id"].(string); !ok {
				return errors.New("invalid version data: missing or invalid node_id")
			}
			if _, ok := data["chain_id"].(string); !ok {
				return errors.New("invalid version data: missing or invalid chain_id")
			}
			if _, ok := data["block_height"].(float64); !ok { // JSON numbers are decoded as float64
				return errors.New("invalid version data: missing or invalid block_height")
			}
			if _, ok := data["nonce"].(string); !ok {
				return errors.New("invalid version data: missing or invalid nonce")
			}
		} else {
			return errors.New("invalid version data: must be a map")
		}
	case "verack":
		// Validate that Data is a string (node ID)
		if _, ok := m.Data.(string); !ok {
			return errors.New("invalid verack data: must be node ID string")
		}
	default:
		// Unknown message types are not allowed
		return errors.New("unknown message type")
	}

	// If all validations pass, return nil (no error)
	return nil
}

// Encode serializes the Message struct to JSON bytes.
func (m *Message) Encode() ([]byte, error) {
	// Marshal the message into JSON format
	return json.Marshal(m)
}

// DecodeMessage takes a JSON byte slice and returns a validated Message object.
func DecodeMessage(data []byte) (*Message, error) {
	var msg Message

	// Unmarshal the JSON data into the msg variable
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}

	// Validate the deserialized message
	if err := msg.ValidateMessage(); err != nil {
		return nil, err
	}

	// Return the valid message pointer
	return &msg, nil
}
