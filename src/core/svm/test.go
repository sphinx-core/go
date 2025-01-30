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

package main

import (
	"fmt"

	svm "github.com/sphinx-core/go/src/core/svm/opcodes"
)

func main() {
	tests := []struct {
		op   svm.OpCode
		a, b uint64
		n    uint
		name string
	}{
		{svm.Xor, 5, 3, 0, "Xor"},
		{svm.Or, 5, 3, 0, "Or"},
		{svm.And, 5, 3, 0, "And"},
		{svm.Rot, 5, 0, 1, "Rot"},
		{svm.Not, 5, 0, 0, "Not"},
		{svm.Shr, 16, 0, 2, "Shr"},
		{svm.Add, 10, 15, 0, "Add"},
	}

	for _, test := range tests {
		result := svm.ExecuteOp(test.op, test.a, test.b, test.n)
		fmt.Printf("%s(0x%x, 0x%x, 0x%x) = 0x%x (%d)\n", test.name, test.a, test.b, test.n, uint64(result), int64(result))
	}
}
