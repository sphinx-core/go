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

package params

import (
	"errors"

	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
)

// SPHINCSParameters wraps the SPHINCS+ parameter configuration.
type SPHINCSParameters struct {
	Params *parameters.Parameters
}

// NewSPHINCSParameters initializes SPHINCS+ parameters for SHAKE256-128f-robust (LV-1 of NIST claimed).
func NewSPHINCSParameters() (*SPHINCSParameters, error) {
	params := parameters.MakeSphincsPlusSHAKE256192fRobust(false)
	if params == nil {
		return nil, errors.New("failed to initialize SPHINCS+ parameters")
	}
	return &SPHINCSParameters{Params: params}, nil
}
