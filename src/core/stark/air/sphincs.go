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
package sign

import (
	"errors"

	"github.com/actuallyachraf/zkstarks"
	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
	key "github.com/sphinx-core/go/src/core/sphincs/key/backend"
)

// SPHINCSSigner implements Signer for SPHINCS+ signatures and integrates with zkstarks
type SPHINCSSigner struct {
	KeyManager *key.KeyManager
}

// NewSPHINCSSigner creates a new signer with keys ready
func NewSPHINCSSigner() (*SPHINCSSigner, error) {
	km, err := key.NewKeyManager()
	if err != nil {
		return nil, err
	}
	return &SPHINCSSigner{KeyManager: km}, nil
}

// VerifySignature verifies a single SPHINCS+ signature for a message and pk
func (s *SPHINCSSigner) VerifySignature(pk *sphincs.SPHINCS_PK, msg, sig []byte) bool {
	return sphincs.Spx_verify(pk, msg, sig)
}

// GenerateSTARKProof creates a STARK proof for the batch of signatures
func (s *SPHINCSSigner) GenerateSTARKProof(batch BatchSignatures) (*STARKProofResult, error) {
	if len(batch.Signatures) != len(batch.Messages) || len(batch.Messages) != len(batch.PublicKeys) {
		return nil, errors.New("batch length mismatch")
	}

	// 1. Construct computation trace encoding the verification of each signature
	//    - For each (pk,msg,sig), verify SPHINCS+ signature
	//    - Encode the steps into a trace compatible with your zkstarks package

	trace, err := s.buildVerificationTrace(batch)
	if err != nil {
		return nil, err
	}

	// 2. Generate the STARK proof for this trace using zkstarks library
	proof, publicInputs, err := zkstarks.GenerateProof(trace)
	if err != nil {
		return nil, err
	}

	return &STARKProofResult{
		Proof:        proof,
		PublicInputs: publicInputs,
	}, nil
}

// VerifySTARKProof verifies the STARK proof that compresses all signatures
func (s *SPHINCSSigner) VerifySTARKProof(proof *STARKProofResult) (bool, error) {
	valid, err := zkstarks.VerifyProof(proof.Proof, proof.PublicInputs)
	return valid, err
}

// buildVerificationTrace builds the computation trace for verifying all PQ signatures
func (s *SPHINCSSigner) buildVerificationTrace(batch BatchSignatures) ([]zkstarks.TraceStep, error) {
	// TODO: Implement domain-specific logic to build the trace representing all PQ signature verifications.
	// This depends on how your zkstarks.TraceStep and DomainParameters are structured.

	// Placeholder: Just return empty trace
	return nil, errors.New("buildVerificationTrace not implemented")
}
