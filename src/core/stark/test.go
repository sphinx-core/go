package main

import (
	"fmt"
	"math/rand"

	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
	"github.com/sphinx-core/go/src/core/sign"
)

// generateTestMessage creates a random test message of specified length.
func generateTestMessage(length int) []byte {
	message := make([]byte, length)
	rand.Read(message)
	return message
}

func main() {
	// Initialize SPHINCS+ parameters (adjust based on your parameters package).
	// Using typical values for SPHINCS+-128s-robust with SHAKE-256.
	sphincsParams := &parameters.Parameters{
		N:         16, // Security parameter (bytes)
		K:         10, // FORS trees
		A:         6,  // FORS tree height
		H:         66, // Hypertree height
		D:         7,  // Hypertree layers
		Len:       34, // WOTS+ signature length
		LogT:      4,  // FORS tree logarithm
		RANDOMIZE: true,
		Tweak:     &parameters.Tweak{Hmsg: hmsgMock, PRFmsg: prfmsgMock}, // Mock tweak functions
	}

	// Initialize SignManager
	sm, err := sign.NewSignManager()
	if err != nil {
		fmt.Println("Failed to create SignManager:", err)
		return
	}
	// Override params for testing (since NewSignManager may set different defaults)
	sm.Params.Params = sphincsParams

	// Test 1: Generate and verify a STARK proof with valid signatures
	fmt.Println("=== Test 1: Valid Signatures ===")
	numSignatures := 5
	signatures := make([]sign.Signature, numSignatures)
	for i := 0; i < numSignatures; i++ {
		// Generate keypair
		sk, pk := sphincs.Spx_keygen(sphincsParams)
		// Generate a random message
		message := generateTestMessage(32)
		// Sign the message
		sig := sphincs.Spx_sign(sphincsParams, message, sk)
		// Create Signature struct
		signatures[i] = sign.Signature{
			Message:   message,
			Signature: sig,
			PublicKey: pk,
		}
		// Verify individual signature
		valid := sm.verifySignature(signatures[i])
		fmt.Printf("Signature %d valid: %v\n", i+1, valid)
		if !valid {
			fmt.Printf("Error: Individual signature %d verification failed\n", i+1)
			return
		}
	}

	// Generate STARK proof
	proof, err := sm.GenerateSTARKProof(signatures)
	if err != nil {
		fmt.Println("Failed to generate STARK proof:", err)
		return
	}
	fmt.Println("STARK proof generated successfully")

	// Verify STARK proof
	valid, err := sm.VerifySTARKProof(proof)
	if err != nil {
		fmt.Println("Failed to verify STARK proof:", err)
		return
	}
	fmt.Printf("STARK proof valid: %v\n", valid)
	if !valid {
		fmt.Println("Error: STARK proof verification failed")
		return
	}

	// Test 2: Test with invalid signature (tampered message)
	fmt.Println("\n=== Test 2: Invalid Signature (Tampered Message) ===")
	invalidSignatures := make([]sign.Signature, 1)
	sk, pk := sphincs.Spx_keygen(sphincsParams)
	message := generateTestMessage(32)
	sig := sphincs.Spx_sign(sphincsParams, message, sk)
	// Tamper the message
	tamperedMessage := append(message, []byte("tamper")...)
	invalidSignatures[0] = sign.Signature{
		Message:   tamperedMessage,
		Signature: sig,
		PublicKey: pk,
	}
	invalidProof, err := sm.GenerateSTARKProof(invalidSignatures)
	if err != nil {
		fmt.Println("Failed to generate STARK proof for invalid signature:", err)
		return
	}
	valid, err = sm.VerifySTARKProof(invalidProof)
	if err != nil {
		fmt.Println("Error during invalid STARK proof verification:", err)
	} else if valid {
		fmt.Println("Error: Invalid STARK proof unexpectedly verified")
	} else {
		fmt.Println("Invalid STARK proof correctly rejected")
	}

	// Test 3: Test serialization and deserialization of a signature
	fmt.Println("\n=== Test 3: Signature Serialization/Deserialization ===")
	sigBytes, err := signatures[0].Signature.SerializeSignature()
	if err != nil {
		fmt.Println("Failed to serialize signature:", err)
		return
	}
	deserializedSig, err := sphincs.DeserializeSignature(sphincsParams, sigBytes)
	if err != nil {
		fmt.Println("Failed to deserialize signature:", err)
		return
	}
	// Verify deserialized signature
	valid = sphincs.Spx_verify(sphincsParams, signatures[0].Message, deserializedSig, signatures[0].PublicKey)
	fmt.Printf("Deserialized signature valid: %v\n", valid)
	if !valid {
		fmt.Println("Error: Deserialized signature verification failed")
		return
	}

	// Test 4: Test with empty signatures
	fmt.Println("\n=== Test 4: Empty Signatures ===")
	_, err = sm.GenerateSTARKProof([]sign.Signature{})
	if err == nil {
		fmt.Println("Error: Empty signatures should have caused an error")
		return
	}
	fmt.Println("Empty signatures correctly rejected:", err)

	// Test 5: Test with too many signatures
	fmt.Println("\n=== Test 5: Too Many Signatures ===")
	largeSignatures := make([]sign.Signature, 1025)
	for i := 0; i < 1025; i++ {
		sk, pk := sphincs.Spx_keygen(sphincsParams)
		message := generateTestMessage(32)
		sig := sphincs.Spx_sign(sphincsParams, message, sk)
		largeSignatures[i] = sign.Signature{
			Message:   message,
			Signature: sig,
			PublicKey: pk,
		}
	}
	_, err = sm.GenerateSTARKProof(largeSignatures)
	if err == nil {
		fmt.Println("Error: Too many signatures should have caused an error")
		return
	}
	fmt.Println("Too many signatures correctly rejected:", err)

	fmt.Println("\nAll tests completed successfully!")
}

// Mock Tweak functions (replace with actual implementations from your parameters package)
func hmsgMock(r, pkSeed, pkRoot, m []byte) []byte {
	// Placeholder: Concatenate inputs and return (simplified)
	return append(append(append(r, pkSeed...), pkRoot...), m...)
}

func prfmsgMock(skPrf, opt, m []byte) []byte {
	// Placeholder: Concatenate inputs and return (simplified)
	return append(append(skPrf, opt...), m...)
}
