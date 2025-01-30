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

// Bitwise operation for XOR
func XorOp(a, b uint64) uint64 {
	return a ^ b
}

// Bitwise operation for OR
func OrOp(a, b uint64) uint64 {
	return a | b
}

// Bitwise operation for AND
func AndOp(a, b uint64) uint64 {
	return a & b
}

// Bitwise rotation (circular shift)
func RotOp(a uint64, n uint) uint64 {
	return (a << n) | (a >> (64 - n))
}

// Bitwise NOT (inverts all bits)
func NotOp(a uint64) uint64 {
	return ^a
}

// Bitwise right shift
func ShrOp(a uint64, n uint) uint64 {
	return a >> n
}

// Add (mod 2^64) operation (mod 2^64, equivalent to overflow behavior of uint64)
func AddOp(a, b uint64) uint64 {
	return a + b // Go will naturally overflow here
}

// Add (mod 2^32) operation (mod 2^32, equivalent to overflow behavior of uint32)
func AddOp32(a, b uint64) uint64 {
	return (a + b) % (1 << 32) // mod 2^32
}
