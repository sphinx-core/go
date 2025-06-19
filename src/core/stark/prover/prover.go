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

package prover

import (
	"errors"
	"unsafe"

	"github.com/sphinx-core/go/src/core/stark/air"
)

/*
#cgo LDFLAGS: -L${SRCDIR}/../../libstark -lstark_wrapper -lstark -lgmp -lboost_system -lboost_filesystem
#cgo CXXFLAGS: -I${SRCDIR}/../../libstark/include
#include "../../cwrapper/stark_wrapper.h"
*/
import "C"

// Prover wraps the STARK prover
type Prover struct {
	ptr *C.void
}

// NewProver initializes a STARK prover
func NewProver(air *air.SphincsAIR) (*Prover, error) {
	airConfig := C.CString(`{"field":"GF2_64"}`)
	paramsJson := C.CString(`{
        "fri": {"fri_step_list": [1,2,2], "last_layer_degree_bound": 1, "n_queries": 30, "proof_of_work_bits": 20},
        "log_n_cosets": 2
    }`)
	ptr := C.init_prover(airConfig, paramsJson)
	C.free(unsafe.Pointer(airConfig))
	C.free(unsafe.Pointer(paramsJson))
	if ptr == nil {
		return nil, errors.New("failed to initialize prover")
	}
	return &Prover{ptr: ptr}, nil
}

// GenerateProof generates a zk-STARK proof
func (p *Prover) GenerateProof(sigBytes, message, pkBytes, merkleRoot []byte) ([]byte, error) {
	proofBuf := make([]byte, 10*1024) // Max 10 KB
	proofLen := C.size_t(len(proofBuf))
	result := C.generate_proof(p.ptr,
		(*C.uchar)(unsafe.Pointer(&sigBytes[0])), C.size_t(len(sigBytes)),
		(*C.uchar)(unsafe.Pointer(&message[0])), C.size_t(len(message)),
		(*C.uchar)(unsafe.Pointer(&pkBytes[0])), C.size_t(len(pkBytes)),
		(*C.uchar)(unsafe.Pointer(&merkleRoot[0])), C.size_t(len(merkleRoot)),
		(*C.uchar)(unsafe.Pointer(&proofBuf[0])), &proofLen)
	if result != 0 {
		return nil, errors.New("failed to generate proof")
	}
	return proofBuf[:proofLen], nil
}

// Close frees the prover
func (p *Prover) Close() {
	C.free_prover(p.ptr)
}
