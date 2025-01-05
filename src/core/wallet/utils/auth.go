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

package utils

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

// GenerateHMAC generates a keyed-hash message authentication code (HMAC) using SHA-256.
func GenerateHMAC(data []byte, key string) ([]byte, error) {
	h := hmac.New(sha256.New, []byte(key))
	_, err := h.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to write data to HMAC: %v", err)
	}
	return h.Sum(nil), nil
}

// VerifyHMAC verifies whether the HMAC of the given data matches the expected HMAC value.
func VerifyHMAC(data []byte, key string, expectedHMAC []byte) (bool, error) {
	actualHMAC, err := GenerateHMAC(data, key)
	if err != nil {
		return false, fmt.Errorf("failed to generate HMAC: %v", err)
	}

	if !hmac.Equal(actualHMAC, expectedHMAC) {
		return false, nil
	}

	return true, nil
}
