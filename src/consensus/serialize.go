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

// go/src/consensus/serialize.go
package consensus

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/sphinx-core/go/src/core/hashtree"
)

// Serialize the signed message to bytes
func (sm *SignedMessage) Serialize() ([]byte, error) {
	var buf bytes.Buffer

	// Write signature length and data
	binary.Write(&buf, binary.BigEndian, uint32(len(sm.Signature)))
	buf.Write(sm.Signature)

	// Write timestamp length and data (flexible size)
	binary.Write(&buf, binary.BigEndian, uint32(len(sm.Timestamp)))
	buf.Write(sm.Timestamp)

	// Write nonce length and data (flexible size)
	binary.Write(&buf, binary.BigEndian, uint32(len(sm.Nonce)))
	buf.Write(sm.Nonce)

	// Write merkle root hash (32 bytes)
	if sm.MerkleRoot != nil && sm.MerkleRoot.Hash != nil {
		rootBytes := sm.MerkleRoot.Hash.Bytes()
		if len(rootBytes) < 32 {
			padded := make([]byte, 32)
			copy(padded, rootBytes)
			buf.Write(padded)
		} else {
			buf.Write(rootBytes[:32])
		}
	} else {
		buf.Write(make([]byte, 32))
	}

	// Write original data
	binary.Write(&buf, binary.BigEndian, uint32(len(sm.Data)))
	buf.Write(sm.Data)

	return buf.Bytes(), nil
}

// DeserializeSignedMessage parses bytes into a SignedMessage
func DeserializeSignedMessage(data []byte) (*SignedMessage, error) {
	if len(data) < 16 { // Minimum reasonable size
		return nil, errors.New("signed message too short")
	}

	buf := bytes.NewReader(data)
	msg := &SignedMessage{}

	// Read signature
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return nil, err
	}
	msg.Signature = make([]byte, sigLen)
	if _, err := buf.Read(msg.Signature); err != nil {
		return nil, err
	}

	// Read timestamp (variable size)
	var timestampLen uint32
	if err := binary.Read(buf, binary.BigEndian, &timestampLen); err != nil {
		return nil, err
	}
	msg.Timestamp = make([]byte, timestampLen)
	if _, err := buf.Read(msg.Timestamp); err != nil {
		return nil, err
	}

	// Read nonce (variable size)
	var nonceLen uint32
	if err := binary.Read(buf, binary.BigEndian, &nonceLen); err != nil {
		return nil, err
	}
	msg.Nonce = make([]byte, nonceLen)
	if _, err := buf.Read(msg.Nonce); err != nil {
		return nil, err
	}

	// Read merkle root (32 bytes)
	merkleBytes := make([]byte, 32)
	if _, err := buf.Read(merkleBytes); err != nil {
		return nil, err
	}
	msg.MerkleRoot = &hashtree.HashTreeNode{
		Hash: BytesToUint256(merkleBytes),
	}

	// Read original data
	var dataLen uint32
	if err := binary.Read(buf, binary.BigEndian, &dataLen); err != nil {
		return nil, err
	}
	msg.Data = make([]byte, dataLen)
	if _, err := buf.Read(msg.Data); err != nil {
		return nil, err
	}

	return msg, nil
}
