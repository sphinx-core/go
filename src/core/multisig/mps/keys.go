package multisig

import (
	"fmt"
	"log"
	"sync"

	key "github.com/sphinx-core/go/src/core/sphincs/key/backend"
	sign "github.com/sphinx-core/go/src/core/sphincs/sign/backend"
)

// NewMultiSig initializes a new multisig with a specified number of participants.
// It creates a KeyManager and a SPHINCS+ manager and prepares the multisig structure.
func NewMultiSig(n int) (*MultiSigManager, error) {
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
	return &MultiSigManager{
		km:         km,                      // Set the key manager
		manager:    manager,                 // Set the SPHINCS+ manager
		quorum:     n,                       // Set the quorum value (minimum number of signatures)
		signatures: make(map[string][]byte), // Initialize the signatures map
		partyPK:    make(map[string][]byte), // Initialize the public key map
		proofs:     make(map[string][]byte), // Initialize the proofs map
		Keys:       make([][]byte, n),       // Initialize the list of keys for n participants
	}, nil
}

// GetIndex returns the index of a given public key (pk) in the list of participant keys.
// It is used to find the position of the public key in the keys array.
func (m *MultiSigManager) GetIndex(pk []byte) int {
	m.mu.RLock()         // Lock for reading to ensure thread-safety while accessing the keys
	defer m.mu.RUnlock() // Unlock after the operation is complete

	// Loop through the list of participant keys to find the index of the provided public key
	for i, key := range m.Keys {
		if fmt.Sprintf("%x", key) == fmt.Sprintf("%x", pk) {
			return i // Return the index if the key matches
		}
	}
	return -1 // Return -1 if the key is not found
}

// AddSig adds a signature to the multisig at the given index corresponding to a participant's public key.
// This method is used to record a signature from a participant in the multisig.
func (m *MultiSigManager) AddSig(index int, sig []byte) error {
	m.mu.Lock()         // Lock for writing to ensure thread-safety while modifying state
	defer m.mu.Unlock() // Unlock after the operation is complete

	if index < 0 || index >= len(m.Keys) {
		log.Printf("Invalid index %d, keys length: %d", index, len(m.Keys))
		return fmt.Errorf("invalid index %d", index)
	}

	// Store the signature indexed by the participant's public key (converted to hex string)
	m.signatures[fmt.Sprintf("%x", m.Keys[index])] = sig
	return nil
}

// AddSigFromPubKey adds a signature to the multisig based on the provided public key (pubKey).
// This method allows for signing directly using the public key instead of the index.
func (m *MultiSigManager) AddSigFromPubKey(pubKey []byte, sig []byte) error {
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
func (m *MultiSigManager) GenerateKeyPair() ([]byte, []byte, error) {
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

// RecoveryKey allows Alice to recover her wallet using proofs from other participants.
// The function takes two parameters:
// - message: The message or data that needs to be signed by the participants for wallet recovery.
// - requiredParticipants: A list of participants whose signatures and proofs are required to perform the recovery.
func (m *MultiSigManager) RecoveryKey(message []byte, requiredParticipants []string) ([]byte, error) {
	// Step 1: Lock the mutex to ensure thread-safety during recovery.
	m.mu.Lock()
	defer m.mu.Unlock()

	// Step 2: Initialize a channel to collect signatures and proofs from goroutines.
	proofChan := make(chan []byte, len(requiredParticipants))

	// Step 3: Initialize a WaitGroup to synchronize goroutines.
	var wg sync.WaitGroup

	// Step 4: Loop through each participant in the requiredParticipants list.
	for _, partyID := range requiredParticipants {
		wg.Add(1)
		go func(partyID string) {
			defer wg.Done()

			// Step 5: Check if the participant has signed the message.
			sig, exists := m.signatures[partyID]
			if !exists {
				return // no signature found for participant, skip this goroutine
			}

			// Step 6: Check if the proof for the participant exists.
			proof, exists := m.proofs[partyID]
			if !exists {
				return // no proof found for participant, skip this goroutine
			}

			// Step 7: Validate the proof for the participant.
			valid, err := m.ValidateProof(partyID, message)
			if err != nil || !valid {
				return // invalid proof, skip this goroutine
			}

			// Step 8: Send the combined signature and proof to the channel.
			proofChan <- append(sig, proof...)
		}(partyID)
	}

	// Step 9: Wait for all goroutines to finish processing.
	wg.Wait()

	// Step 10: Close the channel after all goroutines are done.
	close(proofChan)

	// Step 11: Combine the results from the channel into a single recovery proof slice.
	var finalProof []byte
	for proof := range proofChan {
		finalProof = append(finalProof, proof...)
	}

	// Step 12: Check if enough signatures have been collected to meet the quorum.
	if len(finalProof) < m.quorum {
		return nil, fmt.Errorf("not enough signatures to recover the wallet, need at least %d signatures", m.quorum)
	}

	// Step 13: Return the recovery proof.
	return finalProof, nil
}
