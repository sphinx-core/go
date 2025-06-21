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
	"encoding/binary" // Add for timestamp decoding
	"fmt"
	"log"
	"sync"
	"time" // Add for timestamp validation

	"github.com/holiman/uint256"
	"github.com/sphinx-core/go/src/core/hashtree"
	sigproof "github.com/sphinx-core/go/src/core/proof"
	key "github.com/sphinx-core/go/src/core/sphincs/key/backend"
	sign "github.com/sphinx-core/go/src/core/sphincs/sign"
	"github.com/syndtr/goleveldb/leveldb"
)

// SIPS0008 https://github.com/sphinx-core/sips/wiki/SIPS0008

// MultisigManager manages the SPHINCS+ multisig functionalities, including key generation, signing, and verification.
type MultisigManager struct {
	km         *key.KeyManager
	manager    *sign.SphincsManager
	quorum     int
	signatures map[string][]byte
	partyPK    map[string][]byte
	proofs     map[string][]byte
	// Store timestamp and nonce for each party to prevent signature reuse
	timestamps map[string][]byte
	nonces     map[string][]byte
	storedPK   [][]byte // Public keys
	storedSK   [][]byte // Private keys
	mu         sync.RWMutex
}

// GetStoredPK returns the stored public keys of all participants
func (m *MultisigManager) GetStoredPK() [][]byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.storedPK
}

// GetStoredSK returns the stored private keys of all participants
func (m *MultisigManager) GetStoredSK() [][]byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.storedSK
}

// NewMultiSig initializes a new multisig with a specified number of participants.
// It creates a KeyManager, generates keys for all participants, and prepares the multisig structure.
func NewMultiSig(n int) (*MultisigManager, error) {
	km, err := key.NewKeyManager()
	if err != nil {
		return nil, fmt.Errorf("error initializing KeyManager: %v", err)
	}

	parameters := km.GetSPHINCSParameters()
	// Initialize SphincsManager with a LevelDB instance for storing timestamp-nonce pairs
	db, err := leveldb.OpenFile("src/core/sphincs/hashtree/leaves_db", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open LevelDB: %v", err)
	}

	manager := sign.NewSphincsManager(db, km, parameters)

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
		timestamps: make(map[string][]byte), // Initialize timestamp storage
		nonces:     make(map[string][]byte), // Initialize nonce storage
		storedPK:   pubKeys,
		storedSK:   privKeys,
	}, nil
}

// SignMessage signs a given message using a private key and stores the signature, Merkle root, timestamp, nonce, and proof for the party.
// This method handles the signing of a message and storing the associated signature and proof.
// The timestamp and nonce prevent signature reuse by ensuring each signature is unique and temporally bound.
func (m *MultisigManager) SignMessage(message []byte, privKey []byte, partyID string) ([]byte, []byte, []byte, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	log.Printf("Private Key Length: %d", len(privKey))
	sk, pk, err := m.km.DeserializeKeyPair(privKey, nil)
	if err != nil {
		log.Printf("Failed to deserialize private key: %v", err)
		return nil, nil, nil, nil, fmt.Errorf("failed to deserialize private key:ianza: %v", err)
	}

	// Sign the message with timestamp and nonce to prevent reuse
	// The timestamp ensures the signature is bound to a specific time, preventing reuse of old signatures
	// The nonce ensures each signature is unique, even for identical messages
	sig, merkleRoot, timestamp, nonce, err := m.manager.SignMessage(message, sk)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to sign message: %v", err)
	}

	sigBytes, err := m.manager.SerializeSignature(sig)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to serialize signature: %v", err)
	}

	merkleRootBytes := merkleRoot.Hash.Bytes()

	// Serialize public key for storage
	pkBytes, err := pk.SerializePK()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to serialize public key: %v", err)
	}

	// Store timestamp-nonce pair in LevelDB to detect reuse
	// This ensures Alice cannot reuse a signature, as the unique timestamp-nonce pair will be checked
	timestampNonce := append(timestamp, nonce...)
	err = m.manager.db.Put(timestampNonce, []byte("seen"), nil)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to store timestamp-nonce pair: %v", err)
	}

	// Generate and store proof asynchronously
	go func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.signatures[partyID] = sigBytes
		m.partyPK[partyID] = pkBytes
		m.timestamps[partyID] = timestamp
		m.nonces[partyID] = nonce

		// Generate proof including timestamp and nonce to ensure integrity
		// The proof binds the signature to the message, timestamp, nonce, and public key
		// Alice cannot lie about the signature's context due to this binding
		proof, err := sigproof.GenerateSigProof([][]byte{append(timestamp, append(nonce, message...)...)}, [][]byte{merkleRootBytes}, pkBytes)
		if err != nil {
			log.Printf("Failed to generate proof for partyID %s: %v", partyID, err)
			return
		}
		m.proofs[partyID] = proof
	}()

	return sigBytes, merkleRootBytes, timestamp, nonce, nil
}

// VerifySignatures checks if enough signatures have been collected and if each signature is valid.
// It ensures that the multisig operation can proceed by verifying all signatures and confirming the quorum.
// Timestamp and nonce checks prevent signature reuse.
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
	for partyID, sigBytes := range m.signatures {
		// Step 6: Retrieve the public key, timestamp, and nonce of the participant.
		publicKey := m.partyPK[partyID]
		timestamp := m.timestamps[partyID]
		nonce := m.nonces[partyID]
		if publicKey == nil || timestamp == nil || nonce == nil {
			return false, fmt.Errorf("missing public key, timestamp, or nonce for %s", partyID)
		}

		// Step 7: Check timestamp freshness to prevent reuse of old signatures
		// This ensures Alice cannot reuse an old signature, as outdated timestamps are rejected
		timestampInt := binary.BigEndian.Uint64(timestamp)
		currentTimestamp := uint64(time.Now().Unix())
		if currentTimestamp-timestampInt > 300 { // 5-minute window
			return false, fmt.Errorf("timestamp for %s is too old, possible reuse attempt", partyID)
		}

		// Step 8: Check for signature reuse by verifying timestamp-nonce pair in LevelDB
		// This prevents Alice from reusing a signature, as duplicates are detected
		timestampNonce := append(timestamp, nonce...)
		if _, err := m.manager.db.Get(timestampNonce, nil); err == nil {
			return false, fmt.Errorf("signature reuse detected for %s: timestamp-nonce pair already exists", partyID)
		}

		// Step 9: Deserialize the public key.
		deserializedPK, err := m.km.DeserializePublicKey(publicKey)
		if err != nil {
			// Step 10: Return an error if the public key cannot be deserialized.
			return false, fmt.Errorf("error deserializing public key for %s: %v", partyID, err)
		}

		// Step 11: Deserialize the stored signature.
		sig, err := m.manager.DeserializeSignature(sigBytes)
		if err != nil {
			// Step 12: Return an error if the signature cannot be deserialized.
			return false, fmt.Errorf("error deserializing signature for %s: %v", partyID, err)
		}

		// Step 13: Retrieve the Merkle root hash.
		merkleRootBytes := m.signatures[partyID]
		// Step 14: Create a HashTreeNode with the Merkle root bytes.
		merkleRoot := &hashtree.HashTreeNode{Hash: uint256.NewInt(0).SetBytes(merkleRootBytes)}

		// Step 15: Verify the signature with timestamp and nonce
		// SPHINCS+ ensures cryptographic security, preventing forgery
		// Timestamp and nonce ensure uniqueness and freshness, preventing reuse
		// Merkle root ensures signature integrity
		isValidSig := m.manager.VerifySignature(message, timestamp, nonce, sig, deserializedPK, merkleRoot)
		if isValidSig {
			// Step 16: If the signature is valid, increment the counter.
			validSignatures++
			// Step 17: Store timestamp-nonce pair in LevelDB to prevent future reuse
			err = m.manager.db.Put(timestampNonce, []byte("seen"), nil)
			if err != nil {
				return false, fmt.Errorf("failed to store timestamp-nonce pair for %s: %v", partyID, err)
			}
		} else {
			// Step 18: If the signature is invalid, return false.
			return false, fmt.Errorf("signature from participant %s is invalid", partyID)
		}
	}

	// Step 19: Check if enough valid signatures meet the quorum.
	if validSignatures < m.quorum {
		// Step 20: If not enough valid signatures, return false.
		return false, fmt.Errorf("not enough valid signatures to meet the quorum")
	}

	// Step 21: If all checks pass, return true.
	return true, nil
}

// ValidateProof validates the proof for a specific participant by regenerating it and comparing it with the stored proof.
// This ensures that the proof matches the signature and Merkle root, confirming the integrity of the signature.
// Timestamp and nonce in the proof prevent reuse.
func (m *MultisigManager) ValidateProof(partyID string, message []byte) (bool, error) {
	// Step 1: Lock for reading to ensure thread-safety while accessing the proofs and state.
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Step 2: Retrieve the stored proof for the given partyID.
	storedProof, exists := m.proofs[partyID]
	if !exists {
		// Step 3: If no proof is found, return false with an error.
		return false, fmt.Errorf("no proof found for participant %s", partyID)
	}

	// Step 4: Retrieve the Merkle root hash, timestamp, and nonce.
	merkleRootHash := m.signatures[partyID]
	timestamp := m.timestamps[partyID]
	nonce := m.nonces[partyID]
	if merkleRootHash == nil || timestamp == nil || nonce == nil {
		return false, fmt.Errorf("missing Merkle root, timestamp, or nonce for %s", partyID)
	}

	// Step 5: Initialize a channel to collect proof validation results.
	resultChan := make(chan bool, 1)

	// Step 6: Regenerate the proof in a goroutine.
	go func() {
		// Step 7: Regenerate the proof with timestamp and nonce
		// The proof ensures the signature is bound to the message, timestamp, nonce, and public key
		// Alice cannot lie about the signature’s context due to this binding
		regeneratedProof, err := sigproof.GenerateSigProof([][]byte{append(timestamp, append(nonce, message...)...)}, [][]byte{merkleRootHash}, m.partyPK[partyID])
		if err != nil {
			log.Printf("Failed to regenerate proof for participant %s: %v", partyID, err)
			resultChan <- false
			return
		}

		// Step 8: Verify the proof.
		isValidProof := sigproof.VerifySigProof(storedProof, regeneratedProof)
		resultChan <- isValidProof
	}()

	// Step 9: Wait for the result.
	isValidProof := <-resultChan

	// Step 10: If the proof is invalid, return false.
	if !isValidProof {
		return false, fmt.Errorf("proof for participant %s is invalid", partyID)
	}

	// Step 11: If the proof is valid, return true.
	return true, nil
}
