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

// go/src/core/stark/air/sphincs.go
package stark

import (
	"errors"
	"math/big"

	"github.com/actuallyachraf/algebra/ff"
	"github.com/actuallyachraf/algebra/poly"
	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/sphinx-core/go/src/core/zkstarks"
)

// SphincsAIR represents the AIR for SPHINCS+ signature verification
type SphincsAIR struct {
	Params     *parameters.Parameters
	Message    []byte
	Signature  []byte
	PublicKey  []byte
	MerkleRoot []byte
	Trace      []ff.FieldElement // Computation trace for verification
	Polynomial poly.Polynomial   // Interpolated polynomial over trace
}

// NewSphincsAIR creates an AIR instance and generates the computation trace
func NewSphincsAIR(params *parameters.Parameters, message, sigBytes, pkBytes, merkleRoot []byte) (*SphincsAIR, error) {
	// Validate inputs
	if params == nil || message == nil || sigBytes == nil || pkBytes == nil || merkleRoot == nil {
		return nil, errors.New("invalid input parameters")
	}

	// Generate computation trace (simplified example)
	trace, err := generateVerificationTrace(params, message, sigBytes, pkBytes, merkleRoot)
	if err != nil {
		return nil, err
	}

	// Interpolate polynomial over trace
	domain := generateTraceDomain(len(trace))
	points := generatePoints(domain, trace)
	polynomial := poly.Lagrange(points, zkstarks.PrimeField.Modulus())

	return &SphincsAIR{
		Params:     params,
		Message:    message,
		Signature:  sigBytes,
		PublicKey:  pkBytes,
		MerkleRoot: merkleRoot,
		Trace:      trace,
		Polynomial: polynomial,
	}, nil
}

// generateVerificationTrace creates a simplified computation trace for SPHINCS+ verification
func generateVerificationTrace(params *parameters.Parameters, message, sigBytes, pkBytes, merkleRoot []byte) ([]ff.FieldElement, error) {
	// Placeholder: Simulate trace for SPHINCS+ verification
	// In practice, this would involve stepping through Spx_verify and encoding intermediate states
	trace := make([]ff.FieldElement, 1024) // Example size, adjust based on verification steps
	for i := 0; i < len(trace); i++ {
		// Example: Encode signature bytes as field elements (simplified)
		if i < len(sigBytes) {
			trace[i] = zkstarks.PrimeField.NewFieldElementFromInt64(int64(sigBytes[i]))
		} else {
			trace[i] = zkstarks.PrimeField.NewFieldElementFromInt64(0)
		}
	}
	return trace, nil
}

// generateTraceDomain creates a domain for the trace (similar to GenElems in stark.go)
func generateTraceDomain(size int) []ff.FieldElement {
	g := zkstarks.PrimeFieldGen.Exp(big.NewInt(3145728)) // Same generator as in stark.go
	return zkstarks.GenElems(g, size)
}

// generatePoints pairs domain elements with trace values
func generatePoints(x, y []ff.FieldElement) []poly.Point {
	if len(x) != len(y) {
		panic("mismatched lengths")
	}
	points := make([]poly.Point, len(x))
	for i := 0; i < len(x); i++ {
		points[i] = poly.NewPoint(x[i].Big(), y[i].Big())
	}
	return points
}

// GenerateConstraints produces polynomial constraints for SPHINCS+ verification
func (air *SphincsAIR) GenerateConstraints(g ff.FieldElement) (poly.Polynomial, poly.Polynomial, poly.Polynomial) {
	// Simplified constraints (replace with actual SPHINCS+ verification logic)
	// Example: Constraint that signature bytes match expected values
	num0 := air.Polynomial.Sub(poly.NewPolynomialInts(1), zkstarks.PrimeField.Modulus())
	dem0 := poly.NewPolynomialInts(-1, 1)
	constraint1, _ := num0.Div(dem0, zkstarks.PrimeField.Modulus())

	// Constraint for Merkle root (placeholder)
	num1 := air.Polynomial.Sub(poly.NewPolynomialInts(2338775057), zkstarks.PrimeField.Modulus())
	dem1 := poly.NewPolynomialInts(0, 1).Sub(poly.NewPolynomial([]ff.FieldElement{g.Exp(big.NewInt(1022))}), zkstarks.PrimeField.Modulus())
	constraint2, _ := num1.Div(dem1, zkstarks.PrimeField.Modulus())

	// Constraint for verification logic (placeholder)
	num2 := air.Polynomial.Sub(poly.NewPolynomialInts(0), zkstarks.PrimeField.Modulus())
	dem2 := poly.NewPolynomialInts(0, 1).Sub(poly.NewPolynomialInts(1), nil)
	constraint3, _ := num2.Div(dem2, zkstarks.PrimeField.Modulus())

	return constraint1, constraint2, constraint3
}
