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

package types

import "time"

// Note represents the receipt or note of a transaction.
type Note struct {
	To      string    `json:"to"`      // Recipient (Bob's wallet address)
	From    string    `json:"from"`    // Sender (Alice's wallet address)
	Fee     float64   `json:"fee"`     // Transaction fee
	Storage string    `json:"storage"` // Storage information for the transaction
	Date    time.Time `json:"date"`    // Date when the transaction was created
}

// NewNote creates a new note with the provided details.
func NewNote(to, from string, fee float64, storage string) *Note {
	return &Note{
		To:      to,
		From:    from,
		Fee:     fee,
		Storage: storage,
		Date:    time.Now(),
	}
}
