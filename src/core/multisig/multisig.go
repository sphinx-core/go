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
	"sync"

	"github.com/holiman/uint256"
	"github.com/sphinx-core/go/src/core/hashtree"
	sigproof "github.com/sphinx-core/go/src/core/proof"
	key "github.com/sphinx-core/go/src/core/sphincs/key/backend"
	sign "github.com/sphinx-core/go/src/core/sphincs/sign/backend"
)

// MultisigManager manages the SPHINCS+ multisig functionalities, including key generation, signing, and verification.
type MultisigManager struct {
	km         *key.KeyManager      // Key manager for handling cryptographic keys (key management system)
	manager    *sign.SphincsManager // SPHINCS+ manager for signing and verifying signatures (handles SPHINCS+ operations)
	quorum     int                  // Quorum: minimum number of signatures required for validity
	signatures map[string][]byte    // Store signatures from each participant, indexed by party ID
	partyPK    map[string][]byte    // Store public keys of the participants, indexed by party ID
	proofs     map[string][]byte    // Store proof for each participant, indexed by party ID
	keys       [][]byte             // Store the public keys of all participants in a list for index retrieval
	mu         sync.RWMutex         // Mutex to protect the state of the multisig manager, ensuring thread-safety
}

// NewMultiSig initializes a new multisig with a specified number of participants.
// It creates a KeyManager and a SPHINCS+ manager and prepares the multisig structure.
func NewMultiSig(n int) (*MultisigManager, error) {
	// Initialize the KeyManager to handle cryptographic operations
	km, err := key.NewKeyManager()
	if err != nil {
		// Return an error if the KeyManager cannot be initialized
		return nil, fmt.Errorf("error initializing KeyManager: %v", err)
	}

	// Get the SPHINCS+ parameters required for the SPHINCS manager
	parameters := km.GetSPHINCSParameters()

	// Initialize the SPHINCS+ manager with the parameters and key manager
	manager := sign.NewSphincsManager(nil, km, parameters)

	// Return a new instance of MultisigManager with the initialized components
	return &MultisigManager{
		km:         km,                      // Set the key manager
		manager:    manager,                 // Set the SPHINCS+ manager
		quorum:     n,                       // Set the quorum value (minimum number of signatures)
		signatures: make(map[string][]byte), // Initialize the signatures map
		partyPK:    make(map[string][]byte), // Initialize the public key map
		proofs:     make(map[string][]byte), // Initialize the proofs map
		keys:       make([][]byte, n),       // Initialize the list of keys for n participants
	}, nil
}

// GetIndex returns the index of a given public key (pk) in the list of participant keys.
// It is used to find the position of the public key in the keys array.
func (m *MultisigManager) GetIndex(pk []byte) int {
	m.mu.RLock()         // Lock for reading to ensure thread-safety while accessing the keys
	defer m.mu.RUnlock() // Unlock after the operation is complete

	// Loop through the list of participant keys to find the index of the provided public key
	for i, key := range m.keys {
		if fmt.Sprintf("%x", key) == fmt.Sprintf("%x", pk) {
			return i // Return the index if the key matches
		}
	}
	return -1 // Return -1 if the key is not found
}

// AddSig adds a signature to the multisig at the given index corresponding to a participant's public key.
// This method is used to record a signature from a participant in the multisig.
func (m *MultisigManager) AddSig(index int, sig []byte) error {
	m.mu.Lock()         // Lock for writing to ensure thread-safety while modifying state
	defer m.mu.Unlock() // Unlock after the operation is complete

	// Check if the index is within the valid range of participants
	if index < 0 || index >= len(m.keys) {
		// Return an error if the index is invalid
		return fmt.Errorf("invalid index %d", index)
	}

	// Store the signature indexed by the participant's public key (converted to hex string)
	m.signatures[fmt.Sprintf("%x", m.keys[index])] = sig
	return nil
}

// AddSigFromPubKey adds a signature to the multisig based on the provided public key (pubKey).
// This method allows for signing directly using the public key instead of the index.
func (m *MultisigManager) AddSigFromPubKey(pubKey []byte, sig []byte) error {
	// Retrieve the index for the given public key
	index := m.GetIndex(pubKey)
	if index == -1 {
		// Return an error if the public key is not found in the list of keys
		return fmt.Errorf("public key not found in multisig keys")
	}

	// Call the AddSig method to add the signature at the correct index
	return m.AddSig(index, sig)
}

// GenerateKeyPair generates a new SPHINCS key pair (private and public) for the multisig participant.
func (m *MultisigManager) GenerateKeyPair() ([]byte, []byte, error) {
	// Generate a new key pair using the KeyManager (private and public keys)
	sk, pk, err := m.km.GenerateKey()
	if err != nil {
		// Return an error if key generation fails
		return nil, nil, fmt.Errorf("error generating keys: %v", err)
	}

	// Serialize the private and public keys into byte arrays
	skBytes, pkBytes, err := m.km.SerializeKeyPair(sk, pk)
	if err != nil {
		// Return an error if serialization fails
		return nil, nil, fmt.Errorf("error serializing key pair: %v", err)
	}

	// Return the serialized private and public keys
	return skBytes, pkBytes, nil
}

// SignMessage signs a given message using a private key and stores the signature, Merkle root, and proof for the party.
// This method handles the signing of a message and storing the associated signature and proof.
func (m *MultisigManager) SignMessage(message []byte, privateKey []byte, partyID string) ([]byte, []byte, error) {
	m.mu.Lock()         // Step 1: Lock the mutex for writing to ensure thread-safety while modifying the state.
	defer m.mu.Unlock() // Step 2: Unlock after the operation is complete, ensuring other goroutines can access the data.

	// Step 3: Deserialize the private key (public key is not needed here, so it's nil).
	// Deserialize the key pair from the private key bytes.
	sk, _, err := m.km.DeserializeKeyPair(privateKey, nil)
	if err != nil {
		// Step 4: Log and terminate if the key deserialization fails.
		log.Fatalf("Error deserializing key pair: %v", err)
	}

	// Step 5: Sign the message using the private key.
	// Call the SignMessage method on the SPHINCS+ manager to generate the signature and Merkle root.
	sig, merkleRoot, err := m.manager.SignMessage(message, sk)
	if err != nil {
		// Step 6: Return an error if signing the message fails.
		return nil, nil, fmt.Errorf("failed to sign message: %v", err)
	}

	// Step 7: Serialize the generated signature into a byte slice.
	// This converts the signature object into a byte slice for storage.
	sigBytes, err := m.manager.SerializeSignature(sig)
	if err != nil {
		// Step 8: Return an error if serialization of the signature fails.
		return nil, nil, fmt.Errorf("failed to serialize signature: %v", err)
	}

	// Step 9: Convert the Merkle root to bytes for storage.
	// This is done by calling the `Bytes` method on the Merkle root hash.
	merkleRootBytes := merkleRoot.Hash.Bytes()

	// Step 10: Store the signature for the party identified by partyID.
	// The signature is associated with the partyID in the signatures map.
	m.signatures[partyID] = sigBytes
	// Step 11: Store the public key (private key in this case) for the party.
	// The public key is stored for later verification of the signature.
	m.partyPK[partyID] = privateKey

	// Step 12: Generate proof for the signature.
	// Generate a Merkle proof for the signature using the message and the Merkle root.
	proof, err := sigproof.GenerateSigProof([][]byte{message}, [][]byte{merkleRootBytes}, privateKey)
	if err != nil {
		// Step 13: Return an error if generating the proof fails.
		return nil, nil, fmt.Errorf("failed to generate proof: %v", err)
	}

	// Step 14: Store the generated proof for the party.
	// The proof is associated with the partyID in the proofs map for later validation.
	m.proofs[partyID] = proof

	// Step 15: Return the signature and Merkle root in byte form.
	// These are returned so they can be used by other functions or processes.
	return sigBytes, merkleRootBytes, nil
}

// VerifySignatures checks if enough signatures have been collected and if each signature is valid.
// It ensures that the multisig operation can proceed by verifying all signatures and confirming the quorum.
func (m *MultisigManager) VerifySignatures(message []byte) (bool, error) {
	m.mu.RLock()         // Step 1: Lock for reading to ensure thread-safety while accessing the signatures and state.
	defer m.mu.RUnlock() // Step 2: Unlock after the operation is complete, ensuring other goroutines can access the data.

	// Step 3: Check if the number of collected signatures is less than the quorum.
	// If there are not enough signatures, return false with an error.
	if len(m.signatures) < m.quorum {
		return false, fmt.Errorf("not enough signatures, need at least %d", m.quorum)
	}

	validSignatures := 0 // Step 4: Initialize a counter to keep track of valid signatures.

	// Step 5: Loop through each participant's signature in the signatures map.
	for partyID, sig := range m.signatures {
		// Step 6: Retrieve the public key of the participant using their partyID.
		// This allows verifying the signature associated with that participant.
		publicKey := m.partyPK[partyID]

		// Step 7: Deserialize the public key from the stored bytes.
		// Convert the byte representation of the public key back into a usable public key object.
		deserializedPK, err := m.km.DeserializePublicKey(publicKey)
		if err != nil {
			// Step 8: Return an error if the public key cannot be deserialized.
			return false, fmt.Errorf("error deserializing public key for %s: %v", partyID, err)
		}

		// Step 9: Deserialize the stored signature for the participant.
		// Convert the byte representation of the signature back into a usable signature object.
		sig, err := m.manager.DeserializeSignature(sig)
		if err != nil {
			// Step 10: Return an error if the signature cannot be deserialized.
			return false, fmt.Errorf("error deserializing signature for %s: %v", partyID, err)
		}

		// Step 11: Retrieve the Merkle root hash from the stored signatures for the current party.
		// The Merkle root is used in signature verification to ensure that the signature matches the correct data.
		merkleRootBytes := m.signatures[partyID]
		// Step 12: Create a HashTreeNode with the Merkle root bytes.
		// This is necessary to build a verification tree for the signature.
		merkleRoot := &hashtree.HashTreeNode{Hash: uint256.NewInt(0).SetBytes(merkleRootBytes)}

		// Step 13: Verify the signature using the SPHINCS+ manager's VerifySignature method.
		// The message, signature, deserialized public key, and Merkle root are all required for verification.
		isValidSig := m.manager.VerifySignature(message, sig, deserializedPK, merkleRoot)
		if isValidSig {
			// Step 14: If the signature is valid, increment the validSignatures counter.
			validSignatures++
		} else {
			// Step 15: If the signature is invalid, return false with an error message.
			return false, fmt.Errorf("signature from participant %s is invalid", partyID)
		}
	}

	// Step 16: After looping through all signatures, check if we have enough valid signatures to meet the quorum.
	if validSignatures < m.quorum {
		// Step 17: If not enough valid signatures, return false with an error message.
		return false, fmt.Errorf("not enough valid signatures to meet the quorum")
	}

	// Step 18: If all checks pass, return true indicating that all signatures are valid.
	return true, nil
}

// ValidateProof validates the proof for a specific participant by regenerating it and comparing it with the stored proof.
// This ensures that the proof matches the signature and Merkle root, confirming the integrity of the signature.
func (m *MultisigManager) ValidateProof(partyID string, message []byte) (bool, error) {
	m.mu.RLock()         // Step 1: Lock for reading to ensure thread-safety while accessing the proofs and state.
	defer m.mu.RUnlock() // Step 2: Unlock after the operation is complete, ensuring other goroutines can access the data.

	// Step 3: Retrieve the stored proof for the given partyID.
	// This proof should have been generated earlier during the signing process.
	storedProof, exists := m.proofs[partyID]
	if !exists {
		// Step 4: If no proof is found for the participant, return false with an error message.
		return false, fmt.Errorf("no proof found for participant %s", partyID)
	}

	// Step 5: Retrieve the Merkle root hash stored for the party.
	// This will be used for regenerating the proof.
	merkleRootHash := m.signatures[partyID]

	// Step 6: Regenerate the proof by calling the sigproof.GenerateSigProof function.
	// This uses the message, Merkle root hash, and the participant's public key to generate the proof.
	regeneratedProof, err := sigproof.GenerateSigProof([][]byte{message}, [][]byte{merkleRootHash}, m.partyPK[partyID])
	if err != nil {
		// Step 7: Return an error if the proof regeneration fails.
		return false, fmt.Errorf("failed to regenerate proof: %v", err)
	}

	// Step 8: Verify the stored proof by comparing it with the regenerated proof using the sigproof.VerifySigProof function.
	isValidProof := sigproof.VerifySigProof(storedProof, regeneratedProof)
	// Step 9: Log the result of the proof verification.
	fmt.Printf("Proof verification for participant %s: %v\n", partyID, isValidProof)

	// Step 10: If the proof is invalid, return false with an error message.
	if !isValidProof {
		return false, fmt.Errorf("proof for participant %s is invalid", partyID)
	}

	// Step 11: If the proof is valid, return true indicating successful validation.
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
