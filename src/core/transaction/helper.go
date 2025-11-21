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

// go/src/core/transaction/helper.go
package types

import (
	"encoding/hex"
	"fmt"
)

// Ensure your Block type has these methods to implement consensus.Block
func (b *Block) GetHeight() uint64 {
	return b.Header.Block
}

// GetPrevHash returns the parent block hash as printable string
// This method provides the parent hash for chain continuity verification
func (b *Block) GetPrevHash() string {
	if b.Header == nil || len(b.Header.ParentHash) == 0 {
		return ""
	}

	// Check if it's already a valid string
	parentHashStr := string(b.Header.ParentHash)

	// If it's a genesis hash in text format, return as-is
	if len(parentHashStr) > 8 && parentHashStr[:8] == "GENESIS_" {
		return parentHashStr
	}

	// Otherwise, check if it contains non-printable characters
	for _, r := range parentHashStr {
		if r < 32 || r > 126 {
			// Contains non-printable chars, convert to hex
			return hex.EncodeToString(b.Header.ParentHash)
		}
	}

	// It's already a printable string
	return parentHashStr
}

func (b *Block) GetTimestamp() int64 {
	return b.Header.Timestamp
}

func (b *Block) GetBody() *BlockBody {
	return &b.Body
}

// ValidateHashFormat validates that a hash is in acceptable format
func (b *Block) ValidateHashFormat() error {
	hash := b.GetHash()

	if hash == "" {
		return fmt.Errorf("block hash is empty")
	}

	// Check for non-printable characters
	for i, r := range hash {
		if r < 32 || r > 126 {
			return fmt.Errorf("hash contains non-printable character at position %d: %d", i, r)
		}
	}

	// Check for invalid filename characters
	invalidChars := []rune{'/', '\\', ':', '*', '?', '"', '<', '>', '|', '\x00'}
	for _, char := range invalidChars {
		for _, r := range hash {
			if r == char {
				return fmt.Errorf("hash contains invalid character: %q", char)
			}
		}
	}

	return nil
}
