package main

import (
	"fmt"
	"svm"
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
		fmt.Printf("%s(%d, %d, %d) = %d\n", test.name, test.a, test.b, test.n, result)
	}
}
