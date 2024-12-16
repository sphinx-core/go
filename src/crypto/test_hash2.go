package main

import (
	"crypto/sha256"
	"fmt"
)

func main() {
	// Define three different messages to hash
	messages := [][]byte{
		[]byte("Hello, SHA256!"),
		[]byte("Hello, SHA256!"),
		[]byte("Hash functions are fascinating."),
	}

	// Iterate over the messages and compute their hashes
	for i, data := range messages {
		fmt.Printf("\nMessage %d: %s\n", i+1, data)

		// Compute the SHA-256 hash
		hash := sha256.Sum256(data)
		fmt.Printf("Computed hash: %x\n", hash)

		// Check the length of the computed hash
		if len(hash) != 32 {
			fmt.Printf("Warning: Computed hash for message %d is not 256 bits.\n", i+1)
		} else {
			fmt.Printf("Computed hash for message %d is 256 bits.\n", i+1)
		}
	}
}
