package main

import (
	"fmt"
	"log"

	wots "github.com/sphinx-core/go/src/crypto/WOTS/key"
)

// printKeyOrSignature prints a [][]byte (key or signature) in hex and its total size in bytes
func printKeyOrSignature(name string, data [][]byte) {
	fmt.Printf("%s:\n", name)        // Prints the name of the item (e.g., Private Key, Public Key, Signature)
	totalSize := 0                   // Initializes the total size counter
	for i, component := range data { // Iterates over each component (byte slice) in the data
		fmt.Printf("  Component %d: %x\n", i, component) // Prints the component index and its hex value
		totalSize += len(component)                      // Adds the size of the component to the total size
	}
	fmt.Printf("  Total size: %d bytes\n", totalSize) // Prints the total size in bytes
}

// main is the entry point for the test program
func main() {
	// Test 1: Successful key generation, signing, and verification
	fmt.Println("Test 1: Successful Signing and Verification")

	// Initialize a new KeyManager for Alice
	km, err := wots.NewKeyManager()
	if err != nil {
		log.Fatalf("Failed to create KeyManager: %v", err) // Exits if KeyManager creation fails
	}

	// Print the generated private key in hex and its size
	printKeyOrSignature("Private Key", km.CurrentSK.Key)

	// Define a test message
	message := []byte("Hello, WOTS!")

	// Sign the message and rotate keys, obtaining the signature, current public key, and next public key
	sig, currentPK, nextPK, err := km.SignAndRotate(message)
	if err != nil {
		log.Fatalf("Failed to sign message: %v", err) // Exits if signing fails
	}

	// Print the generated public key in hex and its size
	printKeyOrSignature("Public Key", currentPK.Key)

	// Print the generated signature in hex and its size
	printKeyOrSignature("Signature", sig.Sig)

	// Verify the signature using the current public key
	valid, err := currentPK.Verify(message, sig)
	if err != nil {
		log.Fatalf("Failed to verify signature: %v", err) // Exits if verification fails
	}

	// Print the verification result (expected: true)
	fmt.Printf("Signature valid: %v\n", valid)

	// Print the next public key to confirm key rotation (non-nil)
	fmt.Printf("Next public key exists: %v\n", nextPK != nil)

	// Test 2: Verification with tampered message
	fmt.Println("\nTest 2: Verification with Tampered Message")

	// Define a tampered message
	tamperedMessage := []byte("Hello, WOTS?") // Slightly different message

	// Verify the original signature against the tampered message
	valid, err = currentPK.Verify(tamperedMessage, sig)
	if err != nil {
		log.Fatalf("Failed to verify tampered signature: %v", err) // Exits if verification fails
	}

	// Print the verification result (expected: false)
	fmt.Printf("Signature valid for tampered message: %v\n", valid)

	// Test 3: Verification with modified signature
	fmt.Println("\nTest 3: Verification with Modified Signature")

	// Create a modified signature by altering one byte in the first signature component
	modifiedSig := &wots.Signature{
		Params: sig.Params,                   // Copies the original signature parameters
		Sig:    make([][]byte, len(sig.Sig)), // Allocates a new slice for the modified signature
	}
	for i := range sig.Sig {
		modifiedSig.Sig[i] = make([]byte, len(sig.Sig[i])) // Allocates space for each component
		copy(modifiedSig.Sig[i], sig.Sig[i])               // Copies the original component
	}
	modifiedSig.Sig[0][0] ^= 0xFF // Flips all bits in the first byte of the first component

	// Verify the modified signature against the original message
	valid, err = currentPK.Verify(message, modifiedSig)
	if err != nil {
		log.Fatalf("Failed to verify modified signature: %v", err) // Exits if verification fails
	}

	// Print the verification result (expected: false)
	fmt.Printf("Signature valid for modified signature: %v\n", valid)

	// Test 4: Sign and verify with rotated key
	fmt.Println("\nTest 4: Sign and Verify with Rotated Key")

	// Sign a new message with the rotated key
	newMessage := []byte("Second message")
	newSig, newCurrentPK, _, err := km.SignAndRotate(newMessage)
	if err != nil {
		log.Fatalf("Failed to sign new message: %v", err) // Exits if signing fails
	}

	// Verify the new signature using the new current public key
	valid, err = newCurrentPK.Verify(newMessage, newSig)
	if err != nil {
		log.Fatalf("Failed to verify new signature: %v", err) // Exits if verification fails
	}

	// Print the verification result (expected: true)
	fmt.Printf("New signature valid: %v\n", valid)
}
