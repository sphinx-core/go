package main

import (
	"fmt"
	"log"

	wots "github.com/sphinx-core/go/src/crypto/WOTS/key"
)

// main is the entry point for the test program
func main() {
	// Test 1: Successful key generation, signing, and verification
	fmt.Println("Test 1: Successful Signing and Verification")

	// Initialize a new KeyManager for Alice
	km, err := wots.NewKeyManager()
	if err != nil {
		log.Fatalf("Failed to create KeyManager: %v", err)
	}

	// Define a test message
	message := []byte("Hello, WOTS!")

	// Sign the message and rotate keys, obtaining the signature, current public key, and next public key
	sig, currentPK, nextPK, err := km.SignAndRotate(message)
	if err != nil {
		log.Fatalf("Failed to sign message: %v", err)
	}

	// Verify the signature using the current public key
	valid, err := currentPK.Verify(message, sig)
	if err != nil {
		log.Fatalf("Failed to verify signature: %v", err)
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
		log.Fatalf("Failed to verify tampered signature: %v", err)
	}

	// Print the verification result (expected: false)
	fmt.Printf("Signature valid for tampered message: %v\n", valid)

	// Test 3: Verification with modified signature
	fmt.Println("\nTest 3: Verification with Modified Signature")

	// Create a modified signature by altering one byte in the first signature component
	modifiedSig := &wots.Signature{
		Params: sig.Params,
		Sig:    make([][]byte, len(sig.Sig)),
	}
	for i := range sig.Sig {
		modifiedSig.Sig[i] = make([]byte, len(sig.Sig[i]))
		copy(modifiedSig.Sig[i], sig.Sig[i])
	}
	modifiedSig.Sig[0][0] ^= 0xFF // Flip all bits in the first byte of the first component

	// Verify the modified signature against the original message
	valid, err = currentPK.Verify(message, modifiedSig)
	if err != nil {
		log.Fatalf("Failed to verify modified signature: %v", err)
	}

	// Print the verification result (expected: false)
	fmt.Printf("Signature valid for modified signature: %v\n", valid)

	// Test 4: Sign and verify with rotated key
	fmt.Println("\nTest 4: Sign and Verify with Rotated Key")

	// Sign a new message with the rotated key
	newMessage := []byte("Second message")
	newSig, newCurrentPK, _, err := km.SignAndRotate(newMessage)
	if err != nil {
		log.Fatalf("Failed to sign new message: %v", err)
	}

	// Verify the new signature using the new current public key
	valid, err = newCurrentPK.Verify(newMessage, newSig)
	if err != nil {
		log.Fatalf("Failed to verify new signature: %v", err)
	}

	// Print the verification result (expected: true)
	fmt.Printf("New signature valid: %v\n", valid)
}
