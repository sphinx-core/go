package main

import (
	"fmt"

	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
	params "github.com/sphinx-core/go/src/core/sphincs/config"
	sign "github.com/sphinx-core/go/src/core/stark/zk"
)

// generateSignature creates a SPHINCS+ signature for a given message.
func generateSignature(sphincsParams *params.SPHINCSParameters, message []byte) (sign.Signature, error) {
	// Generate key pair
	sk, pk := sphincs.Spx_keygen(sphincsParams.Params)

	// Sign the message
	sig := sphincs.Spx_sign(sphincsParams.Params, message, sk)

	// Create Signature struct
	signature := sign.Signature{
		Message:   message,
		Signature: sig,
		PublicKey: pk,
	}

	return signature, nil
}

func main() {
	// Initialize SignManager
	sm, err := sign.NewSignManager()
	if err != nil {
		fmt.Printf("Test failed: Failed to create SignManager: %v\n", err)
		return
	}

	// Use the provided NewSPHINCSParameters to initialize parameters
	sphincsParams, err := params.NewSPHINCSParameters()
	if err != nil {
		fmt.Printf("Test failed: Failed to initialize SPHINCS+ parameters: %v\n", err)
		return
	}

	// Test Case 1: Single valid signature
	fmt.Println("Test Case 1: Single valid signature")
	message1 := []byte("test message 1")
	sig1, err := generateSignature(sphincsParams, message1)
	if err != nil {
		fmt.Printf("Test Case 1 failed: Failed to generate signature: %v\n", err)
		return
	}

	// Generate STARK proof
	proof, err := sm.GenerateSTARKProof([]sign.Signature{sig1})
	if err != nil {
		fmt.Printf("Test Case 1 failed: Failed to generate STARK proof: %v\n", err)
		return
	}

	// Verify STARK proof
	valid, err := sm.VerifySTARKProof(proof)
	if err != nil {
		fmt.Printf("Test Case 1 failed: Failed to verify STARK proof: %v\n", err)
		return
	}
	if valid {
		fmt.Println("Test Case 1 passed: STARK proof is valid")
	} else {
		fmt.Println("Test Case 1 failed: STARK proof is invalid")
	}

	// Test Case 2: Multiple valid signatures
	fmt.Println("\nTest Case 2: Multiple valid signatures")
	messages := [][]byte{
		[]byte("test message 1"),
		[]byte("test message 2"),
		[]byte("test message 3"),
	}
	signatures := make([]sign.Signature, len(messages))
	for i, msg := range messages {
		sig, err := generateSignature(sphincsParams, msg)
		if err != nil {
			fmt.Printf("Test Case 2 failed: Failed to generate signature %d: %v\n", i+1, err)
			return
		}
		signatures[i] = sig
	}

	// Generate STARK proof
	proof, err = sm.GenerateSTARKProof(signatures)
	if err != nil {
		fmt.Printf("Test Case 2 failed: Failed to generate STARK proof: %v\n", err)
		return
	}

	// Verify STARK proof
	valid, err = sm.VerifySTARKProof(proof)
	if err != nil {
		fmt.Printf("Test Case 2 failed: Failed to verify STARK proof: %v\n", err)
		return
	}
	if valid {
		fmt.Println("Test Case 2 passed: STARK proof is valid")
	} else {
		fmt.Println("Test Case 2 failed: STARK proof is invalid")
	}

	// Test Case 3: Empty signature list
	fmt.Println("\nTest Case 3: Empty signature list")
	_, err = sm.GenerateSTARKProof([]sign.Signature{})
	if err == nil || err.Error() != "no signatures provided" {
		fmt.Printf("Test Case 3 failed: Expected error 'no signatures provided', got: %v\n", err)
	} else {
		fmt.Println("Test Case 3 passed: Correctly rejected empty signature list")
	}

	// Test Case 4: Invalid signature (tampered message)
	fmt.Println("\nTest Case 4: Invalid signature (tampered message)")
	sigInvalid := sig1
	sigInvalid.Message = []byte("tampered message")
	proof, err = sm.GenerateSTARKProof([]sign.Signature{sigInvalid})
	if err != nil {
		fmt.Printf("Test Case 4 failed: Failed to generate STARK proof: %v\n", err)
		return
	}

	// Verify STARK proof (should fail due to invalid signature)
	valid, err = sm.VerifySTARKProof(proof)
	if err != nil {
		fmt.Printf("Test Case 4 failed: Failed to verify STARK proof: %v\n", err)
		return
	}
	if !valid {
		fmt.Println("Test Case 4 passed: Correctly rejected invalid signature")
	} else {
		fmt.Println("Test Case 4 failed: Accepted invalid signature")
	}

	// Test Case 5: Too many signatures
	fmt.Println("\nTest Case 5: Too many signatures")
	largeSignatures := make([]sign.Signature, 1025)
	for i := 0; i < 1025; i++ {
		sig, err := generateSignature(sphincsParams, []byte(fmt.Sprintf("message %d", i)))
		if err != nil {
			fmt.Printf("Test Case 5 failed: Failed to generate signature %d: %v\n", i+1, err)
			return
		}
		largeSignatures[i] = sig
	}
	_, err = sm.GenerateSTARKProof(largeSignatures)
	if err == nil || err.Error() != "too many signatures; maximum is 1024" {
		fmt.Printf("Test Case 5 failed: Expected error 'too many signatures; maximum is 1024', got: %v\n", err)
	} else {
		fmt.Println("Test Case 5 passed: Correctly rejected too many signatures")
	}

	// Test Case 6: Serialization and deserialization of a signature
	fmt.Println("\nTest Case 6: Serialization and deserialization")
	sigBytes, err := sig1.Signature.SerializeSignature()
	if err != nil {
		fmt.Printf("Test Case 6 failed: Failed to serialize signature: %v\n", err)
		return
	}
	deserializedSig, err := sphincs.DeserializeSignature(sphincsParams.Params, sigBytes)
	if err != nil {
		fmt.Printf("Test Case 6 failed: Failed to deserialize signature: %v\n", err)
		return
	}
	// Verify deserialized signature
	valid = sphincs.Spx_verify(sphincsParams.Params, sig1.Message, deserializedSig, sig1.PublicKey)
	if !valid {
		fmt.Println("Test Case 6 failed: Deserialized signature is invalid")
		return
	}
	fmt.Println("Test Case 6 passed: Signature serialization and deserialization successful")
}
