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

package wots

// Defines the NewWOTSParams function that returns a WOTSParams struct
func NewWOTSParams() WOTSParams {
	// Sets the Winternitz parameter to 16 (fixed)
	w := 16
	// Sets the hash output size to 32 bytes (256 bits for SHAKE256)
	n := 32
	// Sets T1 to 64, calculated as ceil(256 / 4) for w=16
	t1 := 64
	// Sets checksumBits to 11, calculated as ceil(log2(t1 * (w-1))) = ceil(log2(64 * 15))
	checksumBits := 11
	// Sets T2 to 3, calculated as ceil(checksumBits / 4) = ceil(11 / 4)
	t2 := 3
	// Sets T to t1 + t2 (64 + 3 = 67)
	t := t1 + t2

	// Returns a WOTSParams struct with the calculated parameters
	return WOTSParams{
		// Assigns the Winternitz parameter (w=16)
		W: w,
		// Assigns the hash output size (n=32)
		N: n,
		// Assigns the total number of hash chains (t=67)
		T: t,
		// Assigns the number of message chains (t1=64)
		T1: t1,
		// Assigns the number of checksum chains (t2=3)
		T2: t2,
		// Assigns the checksum size in bits (checksumBits=11)
		Checksum: checksumBits,
	}
}
