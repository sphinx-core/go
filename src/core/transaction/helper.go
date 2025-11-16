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
	"errors"
	"math/big"
)

// Ensure your Block type has these methods to implement consensus.Block
func (b *Block) GetHeight() uint64 {
	return b.Header.Block
}

func (b *Block) GetHash() string {
	return hex.EncodeToString(b.Header.Hash)
}

func (b *Block) GetPrevHash() string {
	return hex.EncodeToString(b.Header.PrevHash)
}

func (b *Block) GetTimestamp() int64 {
	return b.Header.Timestamp
}

func (b *Block) Validate() error {
	// Your existing block validation logic
	if b.Header.Block == 0 && len(b.Header.PrevHash) != 0 {
		return errors.New("genesis block must have empty previous hash")
	}
	if b.Header.Block > 0 && len(b.Header.PrevHash) == 0 {
		return errors.New("non-genesis block must have previous hash")
	}
	return nil
}

func (b *Block) GetDifficulty() *big.Int {
	if b.Header.Difficulty != nil {
		return b.Header.Difficulty
	}
	return big.NewInt(1)
}

func (b *Block) GetBody() *BlockBody {
	return &b.Body
}
