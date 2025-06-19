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

// go/src/core/stark/verifier/verifier.go
package verifier

import (
	"errors"
	"unsafe"

	"github.com/sphinx-core/go/src/core/stark/air"
)

/*
#cgo CXXFLAGS: -I${SRCDIR}/../../../crypto/libstark/libstark/src -I${SRCDIR}/../../wrapper -I/opt/homebrew/include
#cgo LDFLAGS: -L${SRCDIR}/../../../crypto/libstark/libstark/build -L/opt/homebrew/lib -lstark -lgmp -lboost_system -lboost_filesystem -ljsoncpp -lssl -lcrypto
#include "stark.h"
*/
import "C"

// Verifier wraps the STARK verifier
type Verifier struct {
	ptr *C.void
}

// NewVerifier initializes a STARK verifier
func NewVerifier(air *air.SphincsAIR) (*Verifier, error) {
	airConfig := C.CString(`{"field":"GF2_64"}`)
	paramsJson := C.CString(`{
        "fri": {"fri_step_list": [1,2,2], "last_layer_degree_bound": 1, "n_queries": 30, "proof_of_work_bits": 20},
        "log_n_cosets": 2
    }`)
	ptr := C.init_verifier(airConfig, paramsJson)
	C.free(unsafe.Pointer(airConfig))
	C.free(unsafe.Pointer(paramsJson))
	if ptr == nil {
		return nil, errors.New("failed to initialize verifier")
	}
	return &Verifier{ptr: ptr}, nil
}

// VerifyProof verifies a zk-STARK proof
func (v *Verifier) VerifyProof(proof, message, pkBytes, merkleRoot []byte) (bool, error) {
	result := C.verify_proof(v.ptr,
		(*C.uchar)(unsafe.Pointer(&proof[0])), C.size_t(len(proof)),
		(*C.uchar)(unsafe.Pointer(&message[0])), C.size_t(len(message)),
		(*C.uchar)(unsafe.Pointer(&pkBytes[0])), C.size_t(len(pkBytes)),
		(*C.uchar)(unsafe.Pointer(&merkleRoot[0])), C.size_t(len(merkleRoot)))
	return result == 0, nil
}

// Close frees the verifier
func (v *Verifier) Close() {
	C.free_verifier(v.ptr)
}
