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

package svm

import (
	"fmt"
)

// OpCode represents an instruction in the SVM
type OpCode byte

// IsPush specifies if an opcode is a PUSH opcode.
func (op OpCode) IsPush() bool {
	switch op {
	// Add PUSH opcodes here in the future
	default:
		return false
	}
}

const (
	// SphinxHash represents a hashing operation in the SVM.
	SphinxHash OpCode = 0x10
)

// stringToOp maps string representations of opcodes to their OpCode values.
var stringToOp = map[string]OpCode{
	"SphinxHash": SphinxHash,
}

// OpCodeFromString returns the OpCode corresponding to a given string, or an error if not found.
func OpCodeFromString(name string) (OpCode, error) {
	if op, exists := stringToOp[name]; exists {
		return op, nil
	}
	return 0, fmt.Errorf("unknown opcode: %s", name)
}
