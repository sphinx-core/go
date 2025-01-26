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
func (m *MultisigManager) GenerateKeyPair() ([]byte, []byte, error) {
	// Generate a new key pair using the KeyManager
	sk, pk, err := m.km.GenerateKey()
	if err != nil {
		// Return error if key generation fails
		return nil, nil, fmt.Errorf("error generating keys: %v", err)
	}

	// Serialize the generated key pair to byte slices (for storage or transmission)
	skBytes, pkBytes, err := m.km.SerializeKeyPair(sk, pk)
	if err != nil {
		// Return error if serialization fails
		return nil, nil, fmt.Errorf("error serializing key pair: %v", err)
	}

	// Return the serialized private and public keys
	return skBytes, pkBytes, nil
}

// SignMessage signs a given message using a private key and stores the signature, Merkle root, and proof for the party
func (m *MultisigManager) SignMessage(message []byte, privateKey []byte, partyID string) ([]byte, []byte, error) {
	// Deserialize the private key from its byte representation
	sk, _, err := m.km.DeserializeKeyPair(privateKey, nil)
	if err != nil {
		log.Fatalf("Error deserializing key pair: %v", err)
	}

	// Sign the message using the SphincsManager (SPHINCS+ signing algorithm)
	sig, merkleRoot, err := m.manager.SignMessage(message, sk)
	if err != nil {
		// Return error if signing fails
		return nil, nil, fmt.Errorf("failed to sign message: %v", err)
	}

	// Serialize the signature to bytes for storage or transmission
	sigBytes, err := m.manager.SerializeSignature(sig)
	if err != nil {
		// Return error if signature serialization fails
		return nil, nil, fmt.Errorf("failed to serialize signature: %v", err)
	}

	// Convert Merkle root to byte slice
	merkleRootBytes := merkleRoot.Hash.Bytes()

	// Store the signature and public key of the participant in the manager's maps
	m.signatures[partyID] = sigBytes
	m.partyPK[partyID] = privateKey

	// Generate a proof for the signed message (used for later verification)
	proof, err := sigproof.GenerateSigProof([][]byte{message}, [][]byte{merkleRootBytes}, privateKey)
	if err != nil {
		// Return error if proof generation fails
		return nil, nil, fmt.Errorf("failed to generate proof: %v", err)
	}

	// Store the proof for the participant
	m.proofs[partyID] = proof

	// Return the serialized signature and Merkle root (as byte slices)
	return sigBytes, merkleRootBytes, nil
}

// VerifySignatures checks if enough signatures have been collected and if each signature is valid
func (m *MultisigManager) VerifySignatures(message []byte) (bool, error) {
	// Check if we have enough signatures to meet the quorum
	if len(m.signatures) < m.quorum {
		return false, fmt.Errorf("not enough signatures, need at least %d", m.quorum)
	}

	// Initialize a counter for valid signatures
	validSignatures := 0

	// Loop through each participant's signature and verify its validity
	for partyID, sig := range m.signatures {
		// Retrieve the public key of the participant
		publicKey := m.partyPK[partyID]
		deserializedPK, err := m.km.DeserializePublicKey(publicKey)
		if err != nil {
			// Return error if public key deserialization fails
			return false, fmt.Errorf("error deserializing public key for %s: %v", partyID, err)
		}

		// Deserialize the signature from its byte representation
		sig, err := m.manager.DeserializeSignature(sig)
		if err != nil {
			// Return error if signature deserialization fails
			return false, fmt.Errorf("error deserializing signature for %s: %v", partyID, err)
		}

		// Retrieve the Merkle root hash associated with this signature
		merkleRootBytes := m.signatures[partyID]

		// Convert Merkle root hash to a *HashTreeNode
		merkleRoot := &hashtree.HashTreeNode{Hash: uint256.NewInt(0).SetBytes(merkleRootBytes)}

		// Verify the signature using the message, signature, public key, and Merkle root
		isValidSig := m.manager.VerifySignature(message, sig, deserializedPK, merkleRoot)
		if isValidSig {
			// If the signature is valid, increment the counter
			validSignatures++
		} else {
			// Return error if the signature is invalid
			return false, fmt.Errorf("signature from participant %s is invalid", partyID)
		}
	}

	// Ensure that the number of valid signatures meets the quorum
	if validSignatures < m.quorum {
		return false, fmt.Errorf("not enough valid signatures to meet the quorum")
	}

	// **Reached here when enough valid signatures t=sig(n_1,...,n_t)) are collected**
	// If we have enough valid signatures, return true
	return true, nil
}

// ValidateProof validates the proof for a specific participant by regenerating it and comparing it with the stored proof
func (m *MultisigManager) ValidateProof(partyID string, message []byte) (bool, error) {
	// Retrieve the stored proof for the participant
	storedProof, exists := m.proofs[partyID]
	if !exists {
		// Return error if no proof exists for the participant
		return false, fmt.Errorf("no proof found for participant %s", partyID)
	}

	// Retrieve the Merkle root hash associated with the participant's signature
	merkleRootHash := m.signatures[partyID]

	// Regenerate the proof using the message and stored Merkle root hash
	regeneratedProof, err := sigproof.GenerateSigProof([][]byte{message}, [][]byte{merkleRootHash}, m.partyPK[partyID])
	if err != nil {
		// Return error if proof regeneration fails
		return false, fmt.Errorf("failed to regenerate proof: %v", err)
	}

	// Verify the proof by comparing the stored proof with the regenerated proof
	isValidProof := sigproof.VerifySigProof(storedProof, regeneratedProof)
	fmt.Printf("Proof verification for participant %s: %v\n", partyID, isValidProof)

	// If the proof is invalid, return error
	if !isValidProof {
		return false, fmt.Errorf("proof for participant %s is invalid", partyID)
	}

	// Return true if the proof is valid
	return true, nil
}
