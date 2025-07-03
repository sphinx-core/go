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

// go/src/core/stark/air/types.go
package sign

import (
	"math/big"

	"github.com/actuallyachraf/algebra/ff"
	"github.com/actuallyachraf/algebra/poly"
	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
	params "github.com/sphinx-core/go/src/core/sphincs/config"
)

// STARKProof represents the STARK proof for multiple SPHINCS+ signatures.
type STARKProof struct {
	DomainParams *DomainParameters // Domain parameters for the STARK proof.
	Signatures   []Signature       // Signatures included in the proof.
	Commitment   []byte            // Merkle root of signatures, messages, and public keys.
	FsChan       *Channel          // Fiat-Shamir channel for non-interactivity.
}

// Signature represents a SPHINCS+ signature with its associated message and public key.
type Signature struct {
	Message   []byte
	Signature *sphincs.SPHINCS_SIG // Uses *sphincs.SPHINCS_SIG
	PublicKey *sphincs.SPHINCS_PK
}

// Channel represents a Fiat-Shamir channel for non-interactive proofs.
type Channel struct {
	State []byte
}

// SignManager manages the aggregation of SPHINCS+ signatures into a STARK proof.
type SignManager struct {
	Params *params.SPHINCSParameters // SPHINCS+ parameters.
}

// NewSignManager initializes a new SignManager with SPHINCS+ parameters.
func NewSignManager() (*SignManager, error) {
	spxParams, err := params.NewSPHINCSParameters()
	if err != nil {
		return nil, err
	}
	return &SignManager{Params: spxParams}, nil
}

// DomainParameters represents the domain parameters for the STARK proof.
type DomainParameters struct {
	Trace                 []ff.FieldElement `json:"computation_trace"`
	GeneratorG            ff.FieldElement   `json:"G_generator"`
	SubgroupG             []ff.FieldElement `json:"G_subgroup"`
	GeneratorH            ff.FieldElement   `json:"H_generator"`
	SubgroupH             []ff.FieldElement `json:"H_subgroup"`
	EvaluationDomain      []ff.FieldElement `json:"evaluation_domain"`
	Polynomial            poly.Polynomial   `json:"interpoland_polynomial"`
	PolynomialEvaluations []*big.Int        `json:"polynomial_evaluations"`
	EvaluationRoot        []byte            `json:"evaluation_commitment"`
}

// JSONDomainParams encodes values properly for safe serialization.
type JSONDomainParams struct {
	Field                 string
	Trace                 []string `json:"computation_trace"`
	GeneratorG            string   `json:"G_generator"`
	SubgroupG             []string `json:"G_subgroup"`
	GeneratorH            string   `json:"H_generator"`
	SubgroupH             []string `json:"H_subgroup"`
	EvaluationDomain      []string `json:"evaluation_domain"`
	Polynomial            []string `json:"interpoland_polynomial"`
	PolynomialEvaluations []string `json:"polynomial_evaluations"`
	EvaluationRoot        string   `json:"evaluation_commitment"`
}
