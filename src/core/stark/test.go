package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
	params "github.com/sphinx-core/go/src/core/sphincs/config"
	sign "github.com/sphinx-core/go/src/core/stark/zk"
)

// generateSignature creates a SPHINCS+ signature for a given message with detailed logging and size measurements.
func generateSignature(sphincsParams *params.SPHINCSParameters, message []byte) (sign.Signature, error) {
	fmt.Printf("  Generating key pair...\n")
	start := time.Now()
	// Generate key pair
	sk, pk := sphincs.Spx_keygen(sphincsParams.Params)
	keyGenDuration := time.Since(start).Seconds()

	// Log key pair details and sizes
	skBytes, err := sk.SerializeSK()
	if err != nil {
		return sign.Signature{}, fmt.Errorf("failed to serialize secret key: %v", err)
	}
	pkBytes, err := pk.SerializePK()
	if err != nil {
		return sign.Signature{}, fmt.Errorf("failed to serialize public key: %v", err)
	}
	fmt.Printf("    Secret Key (hex): %s\n", hex.EncodeToString(skBytes))
	fmt.Printf("    Secret Key size: %.2f KB\n", float64(len(skBytes))/1024.0)
	fmt.Printf("    Public Key (hex): %s\n", hex.EncodeToString(pkBytes))
	fmt.Printf("    Public Key size: %.2f KB\n", float64(len(pkBytes))/1024.0)
	fmt.Printf("    Key generation time: %.3f sec\n", keyGenDuration)

	fmt.Printf("  Signing message: %s\n", string(message))
	start = time.Now()
	// Sign the message
	sig := sphincs.Spx_sign(sphincsParams.Params, message, sk)
	signDuration := time.Since(start).Seconds()

	// Log signature details and size
	sigBytes, err := sig.SerializeSignature()
	if err != nil {
		return sign.Signature{}, fmt.Errorf("failed to serialize signature: %v", err)
	}
	fmt.Printf("    Signature R (hex): %s\n", hex.EncodeToString(sig.R))
	fmt.Printf("    Signature (hex): %s\n", hex.EncodeToString(sigBytes))
	fmt.Printf("    Signature size: %.2f KB\n", float64(len(sigBytes))/1024.0)
	fmt.Printf("    Signature generation time: %.3f sec\n", signDuration)

	// Verify signature
	fmt.Printf("  Verifying signature...\n")
	start = time.Now()
	valid := sphincs.Spx_verify(sphincsParams.Params, message, sig, pk)
	verifyDuration := time.Since(start).Seconds()
	fmt.Printf("    Signature verification result: %v\n", valid)
	fmt.Printf("    Signature verification time: %.3f sec\n", verifyDuration)
	if !valid {
		return sign.Signature{}, fmt.Errorf("generated signature is invalid")
	}

	// Create Signature struct
	signature := sign.Signature{
		Message:   message,
		Signature: sig,
		PublicKey: pk,
	}
	return signature, nil
}

func main() {
	fmt.Println("Initializing STARK proof tests...")

	// Initialize SignManager
	fmt.Println("Creating SignManager...")
	start := time.Now()
	sm, err := sign.NewSignManager()
	if err != nil {
		fmt.Printf("Test failed: Failed to create SignManager: %v\n", err)
		return
	}
	fmt.Printf("SignManager created successfully in %.3f sec.\n", time.Since(start).Seconds())

	// Initialize SPHINCS+ parameters
	fmt.Println("Initializing SPHINCS+ parameters...")
	start = time.Now()
	sphincsParams, err := params.NewSPHINCSParameters()
	if err != nil {
		fmt.Printf("Test failed: Failed to initialize SPHINCS+ parameters: %v\n", err)
		return
	}
	fmt.Printf("SPHINCS+ parameters initialized: N=%d, K=%d, A=%d, H=%d, D=%d, Len=%d, LogT=%d, RANDOMIZE=%v\n",
		sphincsParams.Params.N, sphincsParams.Params.K, sphincsParams.Params.A,
		sphincsParams.Params.H, sphincsParams.Params.D, sphincsParams.Params.Len,
		sphincsParams.Params.LogT, sphincsParams.Params.RANDOMIZE)
	fmt.Printf("Parameters initialization time: %.3f sec\n", time.Since(start).Seconds())

	// Test Case 1: Single valid signature
	fmt.Println("\n=== Test Case 1: Single valid signature ===")
	start = time.Now()
	message1 := []byte("test message 1")
	fmt.Printf("Generating signature for message: %s\n", string(message1))
	sig1, err := generateSignature(sphincsParams, message1)
	if err != nil {
		fmt.Printf("Test Case 1 failed: Failed to generate signature: %v\n", err)
		return
	}

	// Generate STARK proof
	fmt.Println("Generating STARK proof...")
	proofStart := time.Now()
	proof, err := sm.GenerateSTARKProof([]sign.Signature{sig1})
	if err != nil {
		fmt.Printf("Test Case 1 failed: Failed to generate STARK proof: %v\n", err)
		return
	}
	proofGenDuration := time.Since(proofStart).Seconds()
	// Log proof details and size
	fmt.Printf("  Commitment (hex): %s\n", hex.EncodeToString(proof.Commitment))
	fmt.Printf("  Evaluation Root (hex): %s\n", hex.EncodeToString(proof.DomainParams.EvaluationRoot))
	fmt.Printf("  Computation Trace (first 5 elements, hex):")
	for i, elem := range proof.DomainParams.Trace[:min(5, len(proof.DomainParams.Trace))] {
		fmt.Printf(" %s", elem.Big().Text(16))
		if i < min(5, len(proof.DomainParams.Trace))-1 {
			fmt.Print(",")
		}
	}
	fmt.Println()
	fmt.Printf("  Polynomial Evaluations (first 5, hex):")
	for i, eval := range proof.DomainParams.PolynomialEvaluations[:min(5, len(proof.DomainParams.PolynomialEvaluations))] {
		fmt.Printf(" %s", eval.Text(16))
		if i < min(5, len(proof.DomainParams.PolynomialEvaluations))-1 {
			fmt.Print(",")
		}
	}
	fmt.Println()
	proofBytes, err := json.Marshal(proof)
	if err != nil {
		fmt.Printf("Test Case 1 failed: Failed to serialize STARK proof: %v\n", err)
		return
	}
	fmt.Printf("  STARK proof size: %.2f KB\n", float64(len(proofBytes))/1024.0)
	fmt.Printf("  STARK proof generation time: %.3f sec\n", proofGenDuration)
	fmt.Println("STARK proof generated successfully.")

	// Verify STARK proof
	fmt.Println("Verifying STARK proof...")
	verifyStart := time.Now()
	// Log proof details before verification
	fmt.Printf("  Commitment (hex): %s\n", hex.EncodeToString(proof.Commitment))
	fmt.Printf("  Evaluation Root (hex): %s\n", hex.EncodeToString(proof.DomainParams.EvaluationRoot))
	fmt.Printf("  Computation Trace (first 5 elements, hex):")
	for i, elem := range proof.DomainParams.Trace[:min(5, len(proof.DomainParams.Trace))] {
		fmt.Printf(" %s", elem.Big().Text(16))
		if i < min(5, len(proof.DomainParams.Trace))-1 {
			fmt.Print(",")
		}
	}
	fmt.Println()
	fmt.Printf("  Polynomial Evaluations (first 5, hex):")
	for i, eval := range proof.DomainParams.PolynomialEvaluations[:min(5, len(proof.DomainParams.PolynomialEvaluations))] {
		fmt.Printf(" %s", eval.Text(16))
		if i < min(5, len(proof.DomainParams.PolynomialEvaluations))-1 {
			fmt.Print(",")
		}
	}
	fmt.Println()
	valid, err := sm.VerifySTARKProof(proof)
	verifyDuration := time.Since(verifyStart).Seconds()
	if err != nil {
		fmt.Printf("Test Case 1 failed: Failed to verify STARK proof: %v\n", err)
		return
	}
	fmt.Printf("  STARK proof verification time: %.3f sec\n", verifyDuration)
	if valid {
		fmt.Printf("Test Case 1 passed: STARK proof is valid (total time: %.3f sec)\n", time.Since(start).Seconds())
	} else {
		fmt.Printf("Test Case 1 failed: STARK proof is invalid (total time: %.3f sec)\n", time.Since(start).Seconds())
	}

	// Test Case 2: Multiple valid signatures
	fmt.Println("\n=== Test Case 2: Multiple valid signatures ===")
	start = time.Now()
	messages := [][]byte{
		[]byte("test message 1"),
		[]byte("test message 2"),
		[]byte("test message 3"),
	}
	signatures := make([]sign.Signature, len(messages))
	for i, msg := range messages {
		fmt.Printf("Generating signature %d for message: %s\n", i+1, string(msg))
		sig, err := generateSignature(sphincsParams, msg)
		if err != nil {
			fmt.Printf("Test Case 2 failed: Failed to generate signature %d: %v\n", i+1, err)
			return
		}
		signatures[i] = sig
	}

	// Generate STARK proof
	fmt.Println("Generating STARK proof for multiple signatures...")
	proofStart = time.Now()
	proof, err = sm.GenerateSTARKProof(signatures)
	if err != nil {
		fmt.Printf("Test Case 2 failed: Failed to generate STARK proof: %v\n", err)
		return
	}
	proofGenDuration = time.Since(proofStart).Seconds()
	// Log proof details and size
	fmt.Printf("  Commitment (hex): %s\n", hex.EncodeToString(proof.Commitment))
	fmt.Printf("  Evaluation Root (hex): %s\n", hex.EncodeToString(proof.DomainParams.EvaluationRoot))
	fmt.Printf("  Computation Trace (first 5 elements, hex):")
	for i, elem := range proof.DomainParams.Trace[:min(5, len(proof.DomainParams.Trace))] {
		fmt.Printf(" %s", elem.Big().Text(16))
		if i < min(5, len(proof.DomainParams.Trace))-1 {
			fmt.Print(",")
		}
	}
	fmt.Println()
	fmt.Printf("  Polynomial Evaluations (first 5, hex):")
	for i, eval := range proof.DomainParams.PolynomialEvaluations[:min(5, len(proof.DomainParams.PolynomialEvaluations))] {
		fmt.Printf(" %s", eval.Text(16))
		if i < min(5, len(proof.DomainParams.PolynomialEvaluations))-1 {
			fmt.Print(",")
		}
	}
	fmt.Println()
	proofBytes, err = json.Marshal(proof)
	if err != nil {
		fmt.Printf("Test Case 2 failed: Failed to serialize STARK proof: %v\n", err)
		return
	}
	fmt.Printf("  STARK proof size: %.2f KB\n", float64(len(proofBytes))/1024.0)
	fmt.Printf("  STARK proof generation time: %.3f sec\n", proofGenDuration)
	fmt.Println("STARK proof generated successfully.")

	// Verify STARK proof
	fmt.Println("Verifying STARK proof...")
	verifyStart = time.Now()
	// Log proof details before verification
	fmt.Printf("  Commitment (hex): %s\n", hex.EncodeToString(proof.Commitment))
	fmt.Printf("  Evaluation Root (hex): %s\n", hex.EncodeToString(proof.DomainParams.EvaluationRoot))
	fmt.Printf("  Computation Trace (first 5 elements, hex):")
	for i, elem := range proof.DomainParams.Trace[:min(5, len(proof.DomainParams.Trace))] {
		fmt.Printf(" %s", elem.Big().Text(16))
		if i < min(5, len(proof.DomainParams.Trace))-1 {
			fmt.Print(",")
		}
	}
	fmt.Println()
	fmt.Printf("  Polynomial Evaluations (first 5, hex):")
	for i, eval := range proof.DomainParams.PolynomialEvaluations[:min(5, len(proof.DomainParams.PolynomialEvaluations))] {
		fmt.Printf(" %s", eval.Text(16))
		if i < min(5, len(proof.DomainParams.PolynomialEvaluations))-1 {
			fmt.Print(",")
		}
	}
	fmt.Println()
	valid, err = sm.VerifySTARKProof(proof)
	verifyDuration = time.Since(verifyStart).Seconds()
	if err != nil {
		fmt.Printf("Test Case 2 failed: Failed to verify STARK proof: %v\n", err)
		return
	}
	fmt.Printf("  STARK proof verification time: %.3f sec\n", verifyDuration)
	if valid {
		fmt.Printf("Test Case 2 passed: STARK proof is valid (total time: %.3f sec)\n", time.Since(start).Seconds())
	} else {
		fmt.Printf("Test Case 2 failed: STARK proof is invalid (total time: %.3f sec)\n", time.Since(start).Seconds())
	}

	// Test Case 3: Empty signature list
	fmt.Println("\n=== Test Case 3: Empty signature list ===")
	start = time.Now()
	fmt.Println("Attempting to generate STARK proof with empty signature list...")
	_, err = sm.GenerateSTARKProof([]sign.Signature{})
	if err == nil || err.Error() != "no signatures provided" {
		fmt.Printf("Test Case 3 failed: Expected error 'no signatures provided', got: %v (total time: %.3f sec)\n", err, time.Since(start).Seconds())
	} else {
		fmt.Printf("Test Case 3 passed: Correctly rejected empty signature list (total time: %.3f sec)\n", time.Since(start).Seconds())
	}

	// Test Case 4: Invalid signature (tampered message)
	fmt.Println("\n=== Test Case 4: Invalid signature (tampered message) ===")
	start = time.Now()
	sigInvalid := sig1
	sigInvalid.Message = []byte("tampered message")
	fmt.Printf("Using tampered message: %s\n", string(sigInvalid.Message))
	fmt.Println("Generating STARK proof with invalid signature...")
	proofStart = time.Now()
	proof, err = sm.GenerateSTARKProof([]sign.Signature{sigInvalid})
	if err != nil {
		fmt.Printf("Test Case 4 failed: Failed to generate STARK proof: %v (total time: %.3f sec)\n", err, time.Since(start).Seconds())
		return
	}
	proofGenDuration = time.Since(proofStart).Seconds()
	// Log proof details and size
	fmt.Printf("  Commitment (hex): %s\n", hex.EncodeToString(proof.Commitment))
	fmt.Printf("  Evaluation Root (hex): %s\n", hex.EncodeToString(proof.DomainParams.EvaluationRoot))
	fmt.Printf("  Computation Trace (first 5 elements, hex):")
	for i, elem := range proof.DomainParams.Trace[:min(5, len(proof.DomainParams.Trace))] {
		fmt.Printf(" %s", elem.Big().Text(16))
		if i < min(5, len(proof.DomainParams.Trace))-1 {
			fmt.Print(",")
		}
	}
	fmt.Println()
	fmt.Printf("  Polynomial Evaluations (first 5, hex):")
	for i, eval := range proof.DomainParams.PolynomialEvaluations[:min(5, len(proof.DomainParams.PolynomialEvaluations))] {
		fmt.Printf(" %s", eval.Text(16))
		if i < min(5, len(proof.DomainParams.PolynomialEvaluations))-1 {
			fmt.Print(",")
		}
	}
	fmt.Println()
	proofBytes, err = json.Marshal(proof)
	if err != nil {
		fmt.Printf("Test Case 4 failed: Failed to serialize STARK proof: %v (total time: %.3f sec)\n", err, time.Since(start).Seconds())
		return
	}
	fmt.Printf("  STARK proof size: %.2f KB\n", float64(len(proofBytes))/1024.0)
	fmt.Printf("  STARK proof generation time: %.3f sec\n", proofGenDuration)
	fmt.Println("STARK proof generated successfully.")

	// Verify STARK proof
	fmt.Println("Verifying STARK proof (expecting failure due to invalid signature)...")
	verifyStart = time.Now()
	// Log proof details before verification
	fmt.Printf("  Commitment (hex): %s\n", hex.EncodeToString(proof.Commitment))
	fmt.Printf("  Evaluation Root (hex): %s\n", hex.EncodeToString(proof.DomainParams.EvaluationRoot))
	fmt.Printf("  Computation Trace (first 5 elements, hex):")
	for i, elem := range proof.DomainParams.Trace[:min(5, len(proof.DomainParams.Trace))] {
		fmt.Printf(" %s", elem.Big().Text(16))
		if i < min(5, len(proof.DomainParams.Trace))-1 {
			fmt.Print(",")
		}
	}
	fmt.Println()
	fmt.Printf("  Polynomial Evaluations (first 5, hex):")
	for i, eval := range proof.DomainParams.PolynomialEvaluations[:min(5, len(proof.DomainParams.PolynomialEvaluations))] {
		fmt.Printf(" %s", eval.Text(16))
		if i < min(5, len(proof.DomainParams.PolynomialEvaluations))-1 {
			fmt.Print(",")
		}
	}
	fmt.Println()
	valid, err = sm.VerifySTARKProof(proof)
	verifyDuration = time.Since(verifyStart).Seconds()
	if err != nil {
		fmt.Printf("Test Case 4 failed: Failed to verify STARK proof: %v (total time: %.3f sec)\n", err, time.Since(start).Seconds())
		return
	}
	fmt.Printf("  STARK proof verification time: %.3f sec\n", verifyDuration)
	if !valid {
		fmt.Printf("Test Case 4 passed: Correctly rejected invalid signature (total time: %.3f sec)\n", time.Since(start).Seconds())
	} else {
		fmt.Printf("Test Case 4 failed: Accepted invalid signature (total time: %.3f sec)\n", time.Since(start).Seconds())
	}

	// Test Case 5: Too many signatures
	fmt.Println("\n=== Test Case 5: Too many signatures ===")
	start = time.Now()
	fmt.Println("Generating 1025 signatures...")
	largeSignatures := make([]sign.Signature, 1025)
	for i := 0; i < 1025; i++ {
		msg := []byte(fmt.Sprintf("message %d", i))
		fmt.Printf("Generating signature %d for message: %s\n", i+1, string(msg))
		sig, err := generateSignature(sphincsParams, msg)
		if err != nil {
			fmt.Printf("Test Case 5 failed: Failed to generate signature %d: %v (total time: %.3f sec)\n", i+1, err, time.Since(start).Seconds())
			return
		}
		largeSignatures[i] = sig
	}
	fmt.Println("Attempting to generate STARK proof with 1025 signatures...")
	_, err = sm.GenerateSTARKProof(largeSignatures)
	if err == nil || err.Error() != "too many signatures; maximum is 1024" {
		fmt.Printf("Test Case 5 failed: Expected error 'too many signatures; maximum is 1024', got: %v (total time: %.3f sec)\n", err, time.Since(start).Seconds())
	} else {
		fmt.Printf("Test Case 5 passed: Correctly rejected too many signatures (total time: %.3f sec)\n", time.Since(start).Seconds())
	}

	// Test Case 6: Serialization and deserialization of a signature
	fmt.Println("\n=== Test Case 6: Serialization and deserialization ===")
	start = time.Now()
	fmt.Println("Serializing signature...")
	sigBytes, err := sig1.Signature.SerializeSignature()
	if err != nil {
		fmt.Printf("Test Case 6 failed: Failed to serialize signature: %v (total time: %.3f sec)\n", err, time.Since(start).Seconds())
		return
	}
	fmt.Printf("  Serialized signature (hex): %s\n", hex.EncodeToString(sigBytes))
	fmt.Printf("  Serialized signature size: %.2f KB\n", float64(len(sigBytes))/1024.0)

	fmt.Println("Deserializing signature...")
	deserializeStart := time.Now()
	deserializedSig, err := sphincs.DeserializeSignature(sphincsParams.Params, sigBytes)
	deserializeDuration := time.Since(deserializeStart).Seconds()
	if err != nil {
		fmt.Printf("Test Case 6 failed: Failed to deserialize signature: %v (total time: %.3f sec)\n", err, time.Since(start).Seconds())
		return
	}
	fmt.Printf("  Deserialization time: %.3f sec\n", deserializeDuration)
	fmt.Println("Signature deserialized successfully.")

	// Verify deserialized signature
	fmt.Printf("Verifying deserialized signature for message: %s\n", string(sig1.Message))
	verifyStart = time.Now()
	valid = sphincs.Spx_verify(sphincsParams.Params, sig1.Message, deserializedSig, sig1.PublicKey)
	verifyDuration = time.Since(verifyStart).Seconds()
	fmt.Printf("  Deserialized signature verification time: %.3f sec\n", verifyDuration)
	if !valid {
		fmt.Printf("Test Case 6 failed: Deserialized signature is invalid (total time: %.3f sec)\n", time.Since(start).Seconds())
		return
	}
	fmt.Printf("Test Case 6 passed: Signature serialization and deserialization successful (total time: %.3f sec)\n", time.Since(start).Seconds())
}

// min returns the minimum of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
