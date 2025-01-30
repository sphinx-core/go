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

// ExecuteOp processes an operation based on the given opcode (OpCode).
func ExecuteOp(op OpCode, a, b uint64, n uint) uint64 {
	switch op {
	case Xor:
		return XorOp(a, b)
	case Or:
		return OrOp(a, b)
	case And:
		return AndOp(a, b)
	case Rot:
		return RotOp(a, n)
	case Not:
		return NotOp(a)
	case Shr:
		return ShrOp(a, n)
	case Add:
		return AddOp(a, b)
	default:
		panic("Unknown opcode")
	}
}

const (
	// SphinxHash represents a hashing operation in the SVM.
	SphinxHash OpCode = 0x10

	// Adding new opcodes for hashing functions
	SHA3_256      OpCode = 0x11
	SHA512_224    OpCode = 0x12
	SHA512_256    OpCode = 0x13
	SHA3_Shake256 OpCode = 0x14
)

const (
	// Bitwise operation opcodes
	Xor OpCode = 0x20
	Or  OpCode = 0x21
	And OpCode = 0x22
	Rot OpCode = 0x23
	Not OpCode = 0x24
	Shr OpCode = 0x25
	Add OpCode = 0x26
)

// stringToOp maps string representations of opcodes to their OpCode values.
var stringToOp = map[string]OpCode{
	"SphinxHash":    SphinxHash,
	"SHA3_256":      SHA3_256,
	"SHA512_224":    SHA512_224,
	"SHA512_256":    SHA512_256,
	"SHA3_Shake256": SHA3_Shake256,
	"Xor":           Xor,
	"Or":            Or,
	"And":           And,
	"Rot":           Rot,
	"Not":           Not,
	"Shr":           Shr,
	"Add":           Add,
}

// OpCodeFromString returns the OpCode corresponding to a given string, or an error if not found.
func OpCodeFromString(name string) (OpCode, error) {
	if op, exists := stringToOp[name]; exists {
		return op, nil
	}
	return 0, fmt.Errorf("unknown opcode: %s", name)
}
