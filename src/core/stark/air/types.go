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
	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
)

// BatchSignatures holds a block of PQ signatures with messages and public keys
type BatchSignatures struct {
	Signatures [][]byte              // Serialized PQ signatures (e.g. SPHINCS+)
	Messages   [][]byte              // Corresponding messages signed
	PublicKeys []*sphincs.SPHINCS_PK // Corresponding public keys
}

// STARKProofResult contains the generated STARK proof and auxiliary data
type STARKProofResult struct {
	Proof        []byte
	PublicInputs []byte // Serialized public inputs like Merkle roots, commitments etc
}

// Signer interface defines methods for PQ signature verification & proof generation
type Signer interface {
	VerifySignature(pk *sphincs.SPHINCS_PK, msg, sig []byte) bool
	GenerateSTARKProof(batch BatchSignatures) (*STARKProofResult, error)
	VerifySTARKProof(proof *STARKProofResult) (bool, error)
}
