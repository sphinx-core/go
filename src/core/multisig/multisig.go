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

package multisig

import (
	"fmt"
	"log"

	"github.com/holiman/uint256"
	"github.com/sphinx-core/go/src/core/hashtree"
	sigproof "github.com/sphinx-core/go/src/core/proof"
	key "github.com/sphinx-core/go/src/core/sphincs/key/backend"
	sign "github.com/sphinx-core/go/src/core/sphincs/sign/backend"
)

// MultisigManager manages the SPHINCS+ multisig functionalities, including key generation, signing, and verification
type MultisigManager struct {
	km         *key.KeyManager      // Key manager for handling cryptographic keys
	manager    *sign.SphincsManager // SPHINCS+ manager for signing and verifying signatures
	quorum     int                  // Quorum: minimum number of signatures required for validity
	signatures map[string][]byte    // Store signatures from each participant
	partyPK    map[string][]byte    // Store public keys of the participants
	proofs     map[string][]byte    // Store proofs for each participant
}

// NewMultisigManager initializes a new multisig manager with quorum logic
func NewMultisigManager(quorum int) (*MultisigManager, error) {
	// Initialize the KeyManager with default SPHINCS+ parameters.
	// This will be used for cryptographic key management (generation, serialization, etc.)
	km, err := key.NewKeyManager()
	if err != nil {
		// If initialization fails, return an error with a descriptive message
		return nil, fmt.Errorf("error initializing KeyManager: %v", err)
	}

	// Retrieve the SPHINCS+ parameters from the KeyManager
	// These parameters will be used for the signing process
	parameters := km.GetSPHINCSParameters()

	// Initialize the SphincsManager for signing and verification of messages
	// The SphincsManager will handle the SPHINCS+ signature creation and validation
	manager := sign.NewSphincsManager(nil, km, parameters) // 'nil' DB, replace if needed

	// Return the new MultisigManager instance with initialized components
	return &MultisigManager{
		km:         km,                      // KeyManager instance
		manager:    manager,                 // SphincsManager instance
		quorum:     quorum,                  // Threshold for the number of signatures required
		signatures: make(map[string][]byte), // Map to store signatures from participants
		partyPK:    make(map[string][]byte), // Map to store public keys of participants
		proofs:     make(map[string][]byte), // Map to store proof for each participant
	}, nil
}

// GenerateKeyPair generates a new SPHINCS key pair (private and public)
// This function creates a new cryptographic key pair, serializes the keys,
// and returns them for storage or use in signing messages.
func (m *MultisigManager) GenerateKeyPair() ([]byte, []byte, error) {
	// Step 1: Generate a new key pair using the KeyManager.
	// The KeyManager is responsible for securely generating and managing keys.
	// It returns the private key (sk), public key (pk), and any errors encountered.
	sk, pk, err := m.km.GenerateKey()
	if err != nil {
		// Return an error if key generation fails, including the error message.
		return nil, nil, fmt.Errorf("error generating keys: %v", err)
	}

	// Step 2: Serialize the generated key pair to byte slices.
	// Serialization converts the private and public keys into byte slices, making them suitable for storage or transmission.
	skBytes, pkBytes, err := m.km.SerializeKeyPair(sk, pk)
	if err != nil {
		// Return an error if serialization fails, including the error message.
		return nil, nil, fmt.Errorf("error serializing key pair: %v", err)
	}

	// Step 3: Return the serialized private and public keys.
	// These keys are now in byte slice form and can be safely stored or transmitted for future use.
	return skBytes, pkBytes, nil
}

// SignMessage signs a given message using a private key and stores the signature, Merkle root, and proof for the party
// The function signs the message using the private key, stores necessary proof for verification later, and returns the signature.
func (m *MultisigManager) SignMessage(message []byte, privateKey []byte, partyID string) ([]byte, []byte, error) {
	// Step 1: Deserialize the private key from its byte representation.
	// The private key is expected to be serialized (as byte slices), so we need to deserialize it into its original form.
	// We are also deserializing the public key (though we don't use it here).
	sk, _, err := m.km.DeserializeKeyPair(privateKey, nil)
	if err != nil {
		// If deserialization fails, log the error and exit the function.
		log.Fatalf("Error deserializing key pair: %v", err)
	}

	// Step 2: Sign the message using the SPHINCS+ signing algorithm.
	// The `SignMessage` function signs the message with the private key (sk).
	// It also generates the Merkle root (used for proof) along with the signature.
	sig, merkleRoot, err := m.manager.SignMessage(message, sk)
	if err != nil {
		// Return error if signing the message fails, including the error message.
		return nil, nil, fmt.Errorf("failed to sign message: %v", err)
	}

	// Step 3: Serialize the signature to bytes for storage or transmission.
	// The signature is serialized into a byte slice that can be saved or sent securely.
	sigBytes, err := m.manager.SerializeSignature(sig)
	if err != nil {
		// Return error if signature serialization fails, including the error message.
		return nil, nil, fmt.Errorf("failed to serialize signature: %v", err)
	}

	// Step 4: Convert the Merkle root into a byte slice.
	// The Merkle root is an important part of the proof, so we convert it into a byte slice for storage.
	merkleRootBytes := merkleRoot.Hash.Bytes()

	// Step 5: Store the signature and public key of the participant in the manager's maps.
	// `partyID` is used to associate the signature and public key with the specific participant.
	m.signatures[partyID] = sigBytes
	m.partyPK[partyID] = privateKey

	// Step 6: Generate a proof for the signed message.
	// The proof will be used later for verification of the message signature.
	// It uses the message and the Merkle root to generate the proof for this participant.
	proof, err := sigproof.GenerateSigProof([][]byte{message}, [][]byte{merkleRootBytes}, privateKey)
	if err != nil {
		// Return error if proof generation fails, including the error message.
		return nil, nil, fmt.Errorf("failed to generate proof: %v", err)
	}

	// Step 7: Store the proof for the participant.
	// The proof is stored in the `m.proofs` map, indexed by the participant's ID.
	m.proofs[partyID] = proof

	// Step 8: Return the serialized signature and Merkle root as byte slices.
	// These byte slices can now be stored or transmitted securely for later use in the verification process.
	return sigBytes, merkleRootBytes, nil
}

// VerifySignatures checks if enough signatures have been collected and if each signature is valid
// The function returns true if the signatures meet the quorum and are valid, or an error otherwise.
func (m *MultisigManager) VerifySignatures(message []byte) (bool, error) {
	// Step 1: Check if there are enough signatures to meet the quorum.
	// The quorum is the minimum number of signatures required to validate the recovery process.
	if len(m.signatures) < m.quorum {
		// If not enough signatures are collected, return an error
		return false, fmt.Errorf("not enough signatures, need at least %d", m.quorum)
	}

	// Step 2: Initialize a counter to track the number of valid signatures.
	// This will help us ensure that enough valid signatures are collected to meet the quorum.
	validSignatures := 0

	// Step 3: Loop through each participant's signature to verify its validity.
	// We will use the signatures from the `m.signatures` map, indexed by participant's ID (partyID).
	for partyID, sig := range m.signatures {
		// Step 4: Retrieve the public key associated with the participant.
		// The public key is stored in the `partyPK` map, indexed by the participant's ID.
		publicKey := m.partyPK[partyID]

		// Step 5: Deserialize the public key.
		// The public key is stored in a serialized format, so we need to deserialize it into a usable form.
		deserializedPK, err := m.km.DeserializePublicKey(publicKey)
		if err != nil {
			// Return an error if deserialization of the public key fails.
			return false, fmt.Errorf("error deserializing public key for %s: %v", partyID, err)
		}

		// Step 6: Deserialize the signature.
		// The signature is also stored in a serialized format and needs to be deserialized before we can verify it.
		sig, err := m.manager.DeserializeSignature(sig)
		if err != nil {
			// Return an error if deserialization of the signature fails.
			return false, fmt.Errorf("error deserializing signature for %s: %v", partyID, err)
		}

		// Step 7: Retrieve the Merkle root hash for this participant.
		// This hash is part of the proof that helps validate the participant's signature.
		merkleRootBytes := m.signatures[partyID]

		// Step 8: Convert the Merkle root hash into a HashTreeNode structure.
		// The Merkle root is used to verify the integrity of the data and ensure that it hasn't been tampered with.
		merkleRoot := &hashtree.HashTreeNode{Hash: uint256.NewInt(0).SetBytes(merkleRootBytes)}

		// Step 9: Verify the signature.
		// The signature is verified using the message, the deserialized signature, the deserialized public key, and the Merkle root.
		// This step ensures that the signature is valid and corresponds to the message.
		isValidSig := m.manager.VerifySignature(message, sig, deserializedPK, merkleRoot)
		if isValidSig {
			// If the signature is valid, increment the validSignatures counter.
			validSignatures++
		} else {
			// Return an error if the signature is invalid for this participant.
			return false, fmt.Errorf("signature from participant %s is invalid", partyID)
		}
	}

	// Step 10: Ensure that the number of valid signatures meets the quorum.
	// If the number of valid signatures is less than the quorum, return an error indicating failure.
	if validSignatures < m.quorum {
		return false, fmt.Errorf("not enough valid signatures to meet the quorum")
	}

	// Step 11: If enough valid signatures are collected, return true.
	// This indicates that the quorum has been reached and all signatures have been validated successfully.
	// The wallet can now be recovered using the valid signatures.
	return true, nil
}

// ValidateProof validates the proof for a specific participant by regenerating it and comparing it with the stored proof
// It checks if the stored proof corresponds to the regenerated proof using the participant's signature and Merkle root.
func (m *MultisigManager) ValidateProof(partyID string, message []byte) (bool, error) {
	// Step 1: Retrieve the stored proof for the participant from the `proofs` map.
	// This proof was previously generated and stored for this participant.
	storedProof, exists := m.proofs[partyID]
	if !exists {
		// Return an error if no proof is found for the participant.
		return false, fmt.Errorf("no proof found for participant %s", partyID)
	}

	// Step 2: Retrieve the Merkle root hash for the participant from the `signatures` map.
	// This Merkle root is associated with the participant's signature and will be used to regenerate the proof.
	merkleRootHash := m.signatures[partyID]

	// Step 3: Regenerate the proof using the message and stored Merkle root hash.
	// This is done by calling the `GenerateSigProof` function, which creates a proof based on the message and Merkle root.
	regeneratedProof, err := sigproof.GenerateSigProof([][]byte{message}, [][]byte{merkleRootHash}, m.partyPK[partyID])
	if err != nil {
		// Return an error if proof regeneration fails.
		return false, fmt.Errorf("failed to regenerate proof: %v", err)
	}

	// Step 4: Verify the regenerated proof by comparing it with the stored proof.
	// This ensures that the proof is correct and valid.
	isValidProof := sigproof.VerifySigProof(storedProof, regeneratedProof)
	fmt.Printf("Proof verification for participant %s: %v\n", partyID, isValidProof)

	// Step 5: If the proof is invalid, return an error.
	// The proof must match the stored proof for the participant to be considered valid.
	if !isValidProof {
		return false, fmt.Errorf("proof for participant %s is invalid", partyID)
	}

	// Step 6: Return true if the proof is valid.
	// If the proof is valid, we can proceed with using the proof to finalize the wallet recovery process.
	return true, nil
}

// RecoverWallet allows Alice to recover her wallet using proofs from other participants.
// The function takes two parameters:
// - message: The message or data that needs to be signed by the participants for wallet recovery.
// - requiredParticipants: A list of participants whose signatures and proofs are required to perform the recovery.

// The function will return the recovery proof (combination of valid signatures and proofs from participants) if successful,
// or an error if the process fails.
func (m *MultisigManager) RecoveryKey(message []byte, requiredParticipants []string) ([]byte, error) {
	// Step 1: Initialize an empty slice to store the recovery proof.
	// The recovery proof will contain the signatures and proofs of the participants who signed the message.
	var recoveryProof []byte

	// Step 2: Loop through each participant in the requiredParticipants list
	// We are going to gather the signatures and proofs from all the required participants.
	for _, partyID := range requiredParticipants {
		// Step 3: Check if the participant has signed the message.
		// The signatures map holds the signatures for each participant, indexed by their partyID.
		// If the participant has not signed, return an error.
		sig, exists := m.signatures[partyID]
		if !exists {
			// Return an error if the participant's signature is missing
			return nil, fmt.Errorf("no signature found for participant %s", partyID)
		}

		// Step 4: Check if the proof for the participant exists.
		// The proofs map holds the proof for each participant, indexed by their partyID.
		// If the proof is missing, return an error.
		proof, exists := m.proofs[partyID]
		if !exists {
			// Return an error if the participant's proof is missing
			return nil, fmt.Errorf("no proof found for participant %s", partyID)
		}

		// Step 5: Validate the proof for this participant.
		// The ValidateProof method checks if the provided proof for the participant is valid.
		// This step ensures that the participant's proof is correct before adding their signature and proof to the recovery process.
		valid, err := m.ValidateProof(partyID, message)
		if err != nil || !valid {
			// If the proof is invalid or there's an error in validation, return an error indicating invalid proof.
			return nil, fmt.Errorf("invalid proof for participant %s", partyID)
		}

		// Step 6: If the proof is valid, append the signature and proof to the recovery proof.
		// The recovery proof is a combination of valid signatures and proofs from the participants.
		// These will be used to reconstruct the wallet later.
		recoveryProof = append(recoveryProof, sig...)   // Append the participant's signature to the proof
		recoveryProof = append(recoveryProof, proof...) // Append the participant's proof to the proof
	}

	// Step 7: Check if enough signatures have been collected.
	// The wallet recovery requires a minimum number of signatures as defined by the quorum.
	// If not enough signatures are gathered, return an error.
	if len(recoveryProof) < m.quorum {
		return nil, fmt.Errorf("not enough signatures to recover the wallet, need at least %d signatures", m.quorum)
	}

	// Step 8: Return the recovery proof.
	// After collecting and validating the necessary signatures and proofs from the required participants,
	// the recovery proof (a combination of all signatures and proofs) is returned.
	// This proof can now be used to complete the wallet recovery process.
	return recoveryProof, nil
}
