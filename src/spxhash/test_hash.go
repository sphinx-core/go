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

package main

import (
	"fmt"
	"log"

	spxhash "github.com/sphinx-core/go/src/spxhash/hash"
)

func main() {
	// Define three different messages to hash
	messages := [][]byte{
		[]byte("Hello, SphinxHash!"),
		[]byte("Hello, Sphinxhash!"),
		[]byte("Hash functions are fascinating."),
	}

	// Iterate over the messages and compute their hashes
	for i, data := range messages {
		fmt.Printf("\nMessage %d: %s\n", i+1, data)

		// Create a new SphinxHash instance for each message
		sphinx := spxhash.NewSphinxHash(256, []byte{})

		// Write data to the SphinxHash instance
		n, err := sphinx.Write(data)
		if err != nil {
			log.Fatalf("Error writing data for message %d: %v", i+1, err)
		}
		fmt.Printf("Wrote %d bytes to the hash.\n", n)

		// Retrieve the computed hash
		hash := sphinx.Sum(nil) // Sum with nil appends the hash to an empty slice
		fmt.Printf("Computed hash: %x\n", hash)

		// Check the length of the computed hash
		if len(hash) != 32 {
			fmt.Printf("Warning: Computed hash for message %d is not 256 bits.\n", i+1)
		} else {
			fmt.Printf("Computed hash for message %d is 256 bits.\n", i+1)
		}

		// Optional: You can check cache usage by trying to get the hash again
		cachedHash := sphinx.GetHash(data)
		if cachedHash != nil {
			fmt.Printf("Cached hash: %x\n", cachedHash)
		} else {
			fmt.Println("No cached hash found.")
		}
	}
}
