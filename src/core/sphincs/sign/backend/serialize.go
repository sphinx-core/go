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

// go/src/core/sphincs/sign/backend/serialize.go
package sign

import (
	"errors"

	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
)

// SerializeSignature serializes the signature into a byte slice
func (sm *SphincsManager) SerializeSignature(sig *sphincs.SPHINCS_SIG) ([]byte, error) {
	return sig.SerializeSignature() // Calls the signature's built-in SerializeSignature method
}

// DeserializeSignature deserializes a byte slice into a signature
func (sm *SphincsManager) DeserializeSignature(sigBytes []byte) (*sphincs.SPHINCS_SIG, error) {
	// Ensure the SPHINCSParameters are initialized
	if sm.parameters == nil || sm.parameters.Params == nil {
		return nil, errors.New("SPHINCSParameters are not initialized")
	}

	// Extract the internal *parameters.Parameters from SPHINCSParameters
	sphincsParams := sm.parameters.Params

	// Call the SPHINCS method to deserialize the signature using the extracted params
	return sphincs.DeserializeSignature(sphincsParams, sigBytes)
}
