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

// go/src/core/stark/zk/air.go
package zk

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/actuallyachraf/algebra/ff"
	"github.com/actuallyachraf/algebra/nt"
	"github.com/actuallyachraf/algebra/poly"
	"github.com/actuallyachraf/go-merkle"
	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
)

// PrimeField is the finite field used for STARK computations (q = 3221225473).
var PrimeField, _ = ff.NewFiniteField(new(nt.Integer).SetUint64(3221225473))

// PrimeFieldGen is a generator of the field.
var PrimeFieldGen = PrimeField.NewFieldElementFromInt64(5)

// MarshalJSON populates the JSON properly for unexported fields.
func (params *DomainParameters) MarshalJSON() ([]byte, error) {
	if len(params.Trace) == 0 {
		return nil, errors.New("invalid trace in domain parameters: empty trace")
	}
	field := params.Trace[0].Field().Modulus().String()
	trace := make([]string, 0, len(params.Trace))
	for _, e := range params.Trace {
		trace = append(trace, e.Big().String())
	}
	g := params.GeneratorG.Big().String()
	h := params.GeneratorH.Big().String()
	Gsubgroup := make([]string, 0, len(params.SubgroupG))
	Hsubgroup := make([]string, 0, len(params.SubgroupH))
	for _, e := range params.SubgroupG {
		Gsubgroup = append(Gsubgroup, e.Big().String())
	}
	for _, e := range params.SubgroupH {
		Hsubgroup = append(Hsubgroup, e.Big().String())
	}
	evaldomain := make([]string, 0, len(params.EvaluationDomain))
	for _, e := range params.EvaluationDomain {
		evaldomain = append(evaldomain, e.Big().String())
	}
	coeffs := make([]string, 0, len(params.Polynomial))
	for _, e := range params.Polynomial {
		coeffs = append(coeffs, e.String())
	}
	polyEvals := make([]string, 0, len(params.PolynomialEvaluations))
	for _, e := range params.PolynomialEvaluations {
		polyEvals = append(polyEvals, e.String())
	}
	root := hex.EncodeToString(params.EvaluationRoot)
	jsonParams := &JSONDomainParams{
		Field:                 field,
		Trace:                 trace,
		GeneratorG:            g,
		SubgroupG:             Gsubgroup,
		GeneratorH:            h,
		SubgroupH:             Hsubgroup,
		EvaluationDomain:      evaldomain,
		Polynomial:            coeffs,
		PolynomialEvaluations: polyEvals,
		EvaluationRoot:        root,
	}
	return json.MarshalIndent(jsonParams, "", " ")
}

// UnmarshalJSON parses a JSON serialized domain parameters instance.
func (params *DomainParameters) UnmarshalJSON(b []byte) error {
	var jsonDomParams JSONDomainParams
	if err := json.Unmarshal(b, &jsonDomParams); err != nil {
		return err
	}
	filedOrder, ok := new(big.Int).SetString(jsonDomParams.Field, 10)
	if !ok {
		return errors.New("bad number encoding")
	}
	field, _ := ff.NewFiniteField(filedOrder)
	params.Trace = make([]ff.FieldElement, len(jsonDomParams.Trace))
	for i, e := range jsonDomParams.Trace {
		elem, ok := new(big.Int).SetString(e, 10)
		if !ok {
			return errors.New("bad number encoding")
		}
		params.Trace[i] = field.NewFieldElement(elem)
	}
	params.SubgroupG = make([]ff.FieldElement, len(jsonDomParams.SubgroupG))
	params.SubgroupH = make([]ff.FieldElement, len(jsonDomParams.SubgroupH))
	for i, e := range jsonDomParams.SubgroupG {
		elem, ok := new(big.Int).SetString(e, 10)
		if !ok {
			return errors.New("bad number encoding")
		}
		params.SubgroupG[i] = field.NewFieldElement(elem)
	}
	for i, e := range jsonDomParams.SubgroupH {
		elem, ok := new(big.Int).SetString(e, 10)
		if !ok {
			return errors.New("bad number encoding")
		}
		params.SubgroupH[i] = field.NewFieldElement(elem)
	}
	elemG, _ := new(big.Int).SetString(jsonDomParams.GeneratorG, 10)
	elemH, _ := new(big.Int).SetString(jsonDomParams.GeneratorH, 10)
	params.GeneratorG = field.NewFieldElement(elemG)
	params.GeneratorH = field.NewFieldElement(elemH)
	params.EvaluationDomain = make([]ff.FieldElement, len(jsonDomParams.EvaluationDomain))
	for i, e := range jsonDomParams.EvaluationDomain {
		elem, ok := new(big.Int).SetString(e, 10)
		if !ok {
			return errors.New("bad number encoding")
		}
		params.EvaluationDomain[i] = field.NewFieldElement(elem)
	}
	coeffs := make([]ff.FieldElement, len(jsonDomParams.Polynomial))
	for i, e := range jsonDomParams.Polynomial {
		elem, ok := new(big.Int).SetString(e, 10)
		if !ok {
			return errors.New("bad number encoding")
		}
		coeffs[i] = field.NewFieldElement(elem)
	}
	params.Polynomial = poly.NewPolynomial(coeffs)
	params.PolynomialEvaluations = make([]*big.Int, len(jsonDomParams.PolynomialEvaluations))
	for i, e := range jsonDomParams.PolynomialEvaluations {
		elem, ok := new(big.Int).SetString(e, 10)
		if !ok {
			return errors.New("bad number encoding")
		}
		params.PolynomialEvaluations[i] = elem
	}
	var err error
	params.EvaluationRoot, err = hex.DecodeString(jsonDomParams.EvaluationRoot)
	if err != nil {
		return fmt.Errorf("failed to decode evaluation root: %v", err)
	}
	return nil
}

// NewChannel initializes a new Fiat-Shamir channel.
func NewChannel() *Channel {
	return &Channel{State: []byte{}}
}

// Send appends data to the channel state (simplified Fiat-Shamir).
func (c *Channel) Send(data []byte) {
	c.State = append(c.State, data...)
}

// GenerateSTARKProof generates a STARK proof for a list of SPHINCS+ signatures.
func (sm *SignManager) GenerateSTARKProof(signatures []Signature) (*STARKProof, error) {
	if len(signatures) == 0 {
		return nil, errors.New("no signatures provided")
	}
	if len(signatures) > 1024 {
		return nil, errors.New("too many signatures; maximum is 1024")
	}

	// Step 1: Create computation trace for signature verification.
	trace, err := sm.generateVerificationTrace(signatures)
	if err != nil {
		return nil, fmt.Errorf("failed to generate verification trace: %v", err)
	}

	// Step 2: Generate domain parameters for STARK proof.
	a, g, G, hGenerator, H, evalDomain, f, cosetEval, commitmentRoot, fsChan := generateSignatureDomainParameters(trace)

	// Step 3: Commit to signatures, messages, and public keys.
	commitment, err := sm.commitToSignatures(signatures)
	if err != nil {
		return nil, fmt.Errorf("failed to create signature commitment: %v", err)
	}

	// Step 4: Initialize Fiat-Shamir channel with the commitment.
	fsChan.Send(commitment)

	// Step 5: Construct the STARK proof.
	domainParams := &DomainParameters{
		Trace:                 a,
		GeneratorG:            g,
		SubgroupG:             G,
		GeneratorH:            hGenerator,
		SubgroupH:             H,
		EvaluationDomain:      evalDomain,
		Polynomial:            f,
		PolynomialEvaluations: cosetEval,
		EvaluationRoot:        commitmentRoot,
	}

	return &STARKProof{
		DomainParams: domainParams,
		Signatures:   signatures,
		Commitment:   commitment,
		FsChan:       fsChan,
	}, nil
}

// generateVerificationTrace creates a computation trace for verifying SPHINCS+ signatures.
func (sm *SignManager) generateVerificationTrace(signatures []Signature) ([]ff.FieldElement, error) {
	trace := make([]ff.FieldElement, 1024) // Fixed size to match subgroup order.
	for i := 0; i < len(signatures); i++ {
		// Verify each signature and encode the result (1 for valid, 0 for invalid) in the trace.
		valid := sm.verifySignature(signatures[i])
		if valid {
			trace[i] = PrimeField.NewFieldElementFromInt64(1)
		} else {
			trace[i] = PrimeField.NewFieldElementFromInt64(0)
		}
	}
	// Pad the trace with zeros if fewer than 1024 signatures.
	for i := len(signatures); i < 1024; i++ {
		trace[i] = PrimeField.NewFieldElementFromInt64(0)
	}
	return trace, nil
}

// verifySignature checks if a SPHINCS+ signature is valid for the given message and public key.
func (sm *SignManager) verifySignature(sig Signature) bool {
	if sm.Params == nil || sm.Params.Params == nil || sig.Signature == nil || sig.PublicKey == nil || sig.Message == nil {
		return false
	}

	return sphincs.Spx_verify(sm.Params.Params, sig.Message, sig.Signature, sig.PublicKey)
}

// commitToSignatures creates a Merkle tree commitment for signatures, messages, and public keys.
func (sm *SignManager) commitToSignatures(signatures []Signature) ([]byte, error) {
	data := make([][]byte, len(signatures))
	for i, sig := range signatures {
		if sig.Signature == nil || sig.PublicKey == nil || sig.Message == nil {
			return nil, errors.New("invalid signature data")
		}
		pkBytes, err := sig.PublicKey.SerializePK()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize public key: %v", err)
		}
		// Serialize SPHINCS_SIG using SerializeSignature
		sigBytes, err := sig.Signature.SerializeSignature()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize signature: %v", err)
		}
		// Concatenate message, signature, and public key bytes.
		combined := append(append(sig.Message, sigBytes...), pkBytes...)
		data[i] = combined
	}
	return merkle.Root(data), nil
}

// GenElems returns the list of field elements of the subgroup of specified order.
func GenElems(generator ff.FieldElement, order int) []ff.FieldElement {
	var subgroup = make([]ff.FieldElement, order)
	var i int64
	for i = 0; i < int64(order); i++ {
		subgroup[i] = generator.Exp(new(big.Int).SetInt64(i))
	}
	return subgroup
}

// generatePoints creates interpolation points from x and y field elements.
func generatePoints(x, y []ff.FieldElement) []poly.Point {
	if len(x) != len(y) {
		panic("Error: lists must be of the same length")
	}
	interpolationPoints := make([]poly.Point, len(x))
	for i := 0; i < len(x); i++ {
		interpolationPoints[i] = poly.NewPoint(x[i].Big(), y[i].Big())
	}
	return interpolationPoints
}

// generateSignatureDomainParameters generates domain parameters for the STARK proof.
func generateSignatureDomainParameters(trace []ff.FieldElement) ([]ff.FieldElement, ff.FieldElement, []ff.FieldElement, ff.FieldElement, []ff.FieldElement, []ff.FieldElement, poly.Polynomial, []*big.Int, []byte, *Channel) {
	g := PrimeFieldGen.Exp(new(big.Int).SetInt64(3145728))
	G := GenElems(g, 1024)
	points := generatePoints(G[:len(G)-1], trace[:len(G)-1])
	f := poly.Lagrange(points, PrimeField.Modulus())
	hGenerator := PrimeFieldGen.Exp(big.NewInt(393216))
	H := GenElems(hGenerator, 8192)
	evalDomain := make([]ff.FieldElement, 8192)
	for i := 0; i < 8192; i++ {
		evalDomain[i] = PrimeField.Mul(PrimeFieldGen, H[i])
	}
	h := PrimeFieldGen
	hInv := h.Inv()
	// Sanity checks for evaluation domain.
	for i := 0; i < 8192; i++ {
		if !PrimeField.Mul(PrimeField.Mul(hInv, evalDomain[1]).Exp(big.NewInt(int64(i))), h).Equal(evalDomain[i]) {
			panic("error: evaluation domain is incorrect")
		}
	}
	cosetEval := make([]*big.Int, len(evalDomain))
	cosetEvalBytes := make([][]byte, len(evalDomain))
	for i, v := range evalDomain {
		cosetEval[i] = f.Eval(v.Big(), PrimeField.Modulus())
		cosetEvalBytes[i] = cosetEval[i].Bytes()
	}
	commitmentRoot := merkle.Root(cosetEvalBytes)
	fsChan := NewChannel()
	fsChan.Send(commitmentRoot)
	return trace, g, G, hGenerator, H, evalDomain, f, cosetEval, commitmentRoot, fsChan
}

// VerifySTARKProof verifies the STARK proof for the aggregated signatures.
func (sm *SignManager) VerifySTARKProof(proof *STARKProof) (bool, error) {
	if proof == nil || proof.DomainParams == nil || proof.FsChan == nil {
		return false, errors.New("invalid proof structure")
	}

	// Step 1: Verify the signature commitment.
	data := make([][]byte, len(proof.Signatures))
	for i, sig := range proof.Signatures {
		if sig.Signature == nil || sig.PublicKey == nil || sig.Message == nil {
			return false, errors.New("invalid signature data")
		}
		pkBytes, err := sig.PublicKey.SerializePK()
		if err != nil {
			return false, fmt.Errorf("failed to serialize public key: %v", err)
		}
		// Serialize SPHINCS_SIG using SerializeSignature
		sigBytes, err := sig.Signature.SerializeSignature()
		if err != nil {
			return false, fmt.Errorf("failed to serialize signature: %v", err)
		}
		data[i] = append(append(sig.Message, sigBytes...), pkBytes...)
	}
	if computedRoot := merkle.Root(data); !bytesEqual(computedRoot, proof.Commitment) {
		return false, errors.New("signature commitment mismatch")
	}

	// Step 2: Verify the STARK proof (simplified).
	// Check that the trace matches the expected signature verifications.
	trace, err := sm.generateVerificationTrace(proof.Signatures)
	if err != nil {
		return false, fmt.Errorf("failed to regenerate trace: %v", err)
	}
	for i, t := range trace {
		if !t.Equal(proof.DomainParams.Trace[i]) {
			return false, errors.New("trace mismatch")
		}
	}

	// Step 3: Verify polynomial evaluations over the evaluation domain.
	for i, v := range proof.DomainParams.EvaluationDomain {
		expectedEval := proof.DomainParams.Polynomial.Eval(v.Big(), PrimeField.Modulus())
		if expectedEval.Cmp(proof.DomainParams.PolynomialEvaluations[i]) != 0 {
			return false, errors.New("polynomial evaluation mismatch")
		}
	}

	// Step 4: Verify the Merkle commitment.
	cosetEvalBytes := make([][]byte, len(proof.DomainParams.PolynomialEvaluations))
	for i, eval := range proof.DomainParams.PolynomialEvaluations {
		cosetEvalBytes[i] = eval.Bytes()
	}
	if computedRoot := merkle.Root(cosetEvalBytes); !bytesEqual(computedRoot, proof.DomainParams.EvaluationRoot) {
		return false, errors.New("evaluation commitment mismatch")
	}

	return true, nil
}

// bytesEqual compares two byte slices for equality.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
