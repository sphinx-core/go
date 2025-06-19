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
package air

import (
	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
)

// SphincsAIR represents the AIR for SPHINCS+ signature verification
type SphincsAIR struct {
	Params     *sphincs.SPHINCSParams
	Message    []byte
	Signature  []byte
	PublicKey  []byte
	MerkleRoot []byte
}

// NewSphincsAIR creates an AIR instance
func NewSphincsAIR(params *sphincs.SPHINCSParams, message, sigBytes, pkBytes, merkleRoot []byte) (*SphincsAIR, error) {
	return &SphincsAIR{
		Params:     params,
		Message:    message,
		Signature:  sigBytes,
		PublicKey:  pkBytes,
		MerkleRoot: merkleRoot,
	}, nil
}

// Evaluate represents the SPHINCS+ verification circuit (placeholder for C++ AIR)
// Actual constraints are implemented in stark_wrapper.cpp
func (air *SphincsAIR) Evaluate() bool {
	sig, err := sphincs.DeserializeSignature(air.Params, air.Signature)
	if err != nil {
		return false
	}
	pk, err := sphincs.DeserializePK(air.Params, air.PublicKey)
	if err != nil {
		return false
	}
	return sphincs.Spx_verify(air.Params, air.Message, sig, pk)
}
