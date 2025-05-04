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
	"bytes"
	"fmt"
	"log"
	"sync"

	"github.com/holiman/uint256"
	"github.com/sphinx-core/go/src/core/hashtree"
	sigproof "github.com/sphinx-core/go/src/core/proof"
	key "github.com/sphinx-core/go/src/core/sphincs/key/backend"
	sign "github.com/sphinx-core/go/src/core/sphincs/sign/backend"
)

//SIPS0008 https://github.com/sphinx-core/sips/wiki/SIPS0008

// MultisigManager manages the SPHINCS+ multisig functionalities, including key generation, signing, and verification.
type MultisigManager struct {
	km         *key.KeyManager
	manager    *sign.SphincsManager
	quorum     int
	signatures map[string][]byte
	partyPK    map[string][]byte
	proofs     map[string][]byte
	storedPK   [][]byte // Public keys
	storedSK   [][]byte // Private keys (new field)
	mu         sync.RWMutex
}

// GetStoredPK returns the stored public keys of all participants
func (m *MultisigManager) GetStoredPK() [][]byte {
	return m.storedPK
}

// NewMultiSig initializes a new multisig with a specified number of participants.
// It creates a KeyManager, generates keys for all participants, and prepares the multisig structure.
// NewMultiSig initializes a new multisig with a specified number of participants.
func NewMultiSig(n int) (*MultisigManager, error) {
	km, err := key.NewKeyManager()
	if err != nil {
		return nil, fmt.Errorf("error initializing KeyManager: %v", err)
	}

	parameters := km.GetSPHINCSParameters()
	manager := sign.NewSphincsManager(nil, km, parameters)

	pubKeys := make([][]byte, n)
	privKeys := make([][]byte, n)

	for i := 0; i < n; i++ {
		sk, pk, err := km.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("error generating keys for participant %d: %v", i, err)
		}

		skBytes, pkBytes, err := km.SerializeKeyPair(sk, pk)
		if err != nil {
			return nil, fmt.Errorf("error serializing key pair for participant %d: %v", i, err)
		}

		pubKeys[i] = pkBytes
		privKeys[i] = skBytes // Store private keys

		log.Printf("Participant %d Public Key: %x", i+1, pkBytes)
		log.Printf("Participant %d Private Key: %x", i+1, skBytes)

		deserializedSK, deserializedPK, err := km.DeserializeKeyPair(skBytes, pkBytes)
		if err != nil {
			return nil, fmt.Errorf("error deserializing key pair for participant %d: %v", i, err)
		}

		if !bytes.Equal(deserializedSK.SKseed, sk.SKseed) || !bytes.Equal(deserializedSK.SKprf, sk.SKprf) ||
			!bytes.Equal(deserializedSK.PKseed, sk.PKseed) || !bytes.Equal(deserializedSK.PKroot, sk.PKroot) {
			return nil, fmt.Errorf("deserialized private key does not match original for participant %d", i)
		}
		if !bytes.Equal(deserializedPK.PKseed, pk.PKseed) || !bytes.Equal(deserializedPK.PKroot, pk.PKroot) {
			return nil, fmt.Errorf("deserialized public key does not match original for participant %d", i)
		}
		log.Printf("Deserialization check passed for participant %d!", i+1)
	}

	return &MultisigManager{
		km:         km,
		manager:    manager,
		quorum:     n,
		signatures: make(map[string][]byte),
		partyPK:    make(map[string][]byte),
		proofs:     make(map[string][]byte),
		storedPK:   pubKeys,
		storedSK:   privKeys, // Initialize private keys
	}, nil
}

func (m *MultisigManager) GetStoredSK() [][]byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.storedSK
}

// SignMessage signs a given message using a private key and stores the signature, Merkle root, and proof for the party.
// This method handles the signing of a message and storing the associated signature and proof.
func (m *MultisigManager) SignMessage(message []byte, privKey []byte, partyID string) ([]byte, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	log.Printf("Private Key Length: %d", len(privKey))
	sk, pk, err := m.km.DeserializeKeyPair(privKey, nil)
	if err != nil {
		log.Printf("Failed to deserialize private key: %v", err)
		return nil, nil, fmt.Errorf("failed to deserialize private key: %v", err)
	}

	sig, merkleRoot, err := m.manager.SignMessage(message, sk)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign message: %v", err)
	}

	sigBytes, err := m.manager.SerializeSignature(sig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize signature: %v", err)
	}

	merkleRootBytes := merkleRoot.Hash.Bytes()

	// Serialize public key for storage
	pkBytes, err := pk.SerializePK()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize public key: %v", err)
	}

	go func() {
		m.signatures[partyID] = sigBytes
		m.partyPK[partyID] = pkBytes // Store public key

		proof, err := sigproof.GenerateSigProof([][]byte{message}, [][]byte{merkleRootBytes}, pkBytes)
		if err != nil {
			log.Printf("Failed to generate proof for partyID %s: %v", partyID, err)
			return
		}

		m.proofs[partyID] = proof
	}()

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
// ValidateProof validates the proof for a specific participant by regenerating it and comparing it with the stored proof.
func (m *MultisigManager) ValidateProof(partyID string, message []byte) (bool, error) {
	// Step 1: Lock for reading to ensure thread-safety while accessing the proofs and state.
	// The RLock allows multiple goroutines to read concurrently, but no writing can occur while it's held.
	m.mu.RLock()

	// Step 2: Defer the unlocking of the mutex until after the function completes, ensuring no other goroutines are blocked
	// when this function finishes execution.
	defer m.mu.RUnlock()

	// Step 3: Retrieve the stored proof for the given partyID.
	// This proof should have been generated earlier during the signing process.
	storedProof, exists := m.proofs[partyID]
	if !exists {
		// Step 4: If no proof is found for the participant, return false with an error message indicating no proof exists.
		return false, fmt.Errorf("no proof found for participant %s", partyID)
	}

	// Step 5: Retrieve the Merkle root hash stored for the party.
	// This will be used for regenerating the proof.
	merkleRootHash := m.signatures[partyID]

	// Step 6: Initialize a channel to collect proof validation results.
	resultChan := make(chan bool, 1)

	// Step 7: Start a new goroutine to regenerate the proof and verify it.
	go func() {
		// Step 8: Regenerate the proof using the message, Merkle root hash, and the participant's public key.
		regeneratedProof, err := sigproof.GenerateSigProof([][]byte{message}, [][]byte{merkleRootHash}, m.partyPK[partyID])
		if err != nil {
			// Log an error if proof regeneration fails for the participant.
			log.Printf("Failed to regenerate proof for participant %s: %v", partyID, err)
			resultChan <- false
			return
		}

		// Step 9: Verify the proof.
		isValidProof := sigproof.VerifySigProof(storedProof, regeneratedProof)

		// Step 10: Send the result through the channel.
		resultChan <- isValidProof
	}()

	// Step 11: Wait for the goroutine to complete and retrieve the validation result.
	isValidProof := <-resultChan

	// Step 12: If the proof is not valid, return false with an error message indicating the invalid proof.
	if !isValidProof {
		return false, fmt.Errorf("proof for participant %s is invalid", partyID)
	}

	// Step 13: If the proof is valid, return true indicating the proof is valid.
	return true, nil
}
