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

	"github.com/sphinx-core/go/src/core/hashtree"
	sigproof "github.com/sphinx-core/go/src/core/proof"
	key "github.com/sphinx-core/go/src/core/sphincs/key/backend"
	sign "github.com/sphinx-core/go/src/core/sphincs/sign/backend"
	"github.com/sphinx-core/go/src/core/wallet/utils"
)

// MultisigManager manages the SPHINCS+ multisig functionalities
type MultisigManager struct {
	db            *utils.WalletConfig // Corrected to use the exported type
	km            *key.KeyManager
	manager       *sign.SphincsManager
	threshold     int
	signatures    map[string][]byte // Store signatures from participants
	participantPK map[string][]byte // Store public keys of participants
	proofs        map[string][]byte // Store proofs for each participant
}

// NewMultisigManager initializes a new multisig manager
func NewMultisigManager(threshold int) (*MultisigManager, error) {
	// Initialize the walletConfig from utils (this will manage the database)
	db, err := utils.NewWalletConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize wallet config: %v", err)
	}

	// Initialize the KeyManager with default SPHINCS+ parameters.
	km, err := key.NewKeyManager()
	if err != nil {
		return nil, fmt.Errorf("error initializing KeyManager: %v", err)
	}

	// Initialize the SPHINCS+ parameters
	parameters := km.GetSPHINCSParameters()

	// Initialize the SphincsManager with walletConfig and KeyManager
	manager := sign.NewSphincsManager(db.GetDB(), km, parameters) // Use GetDB() method

	return &MultisigManager{
		db:            db,
		km:            km,
		manager:       manager,
		threshold:     threshold,
		signatures:    make(map[string][]byte),
		participantPK: make(map[string][]byte),
		proofs:        make(map[string][]byte),
	}, nil
}

// GenerateKeyPair generates a new SPHINCS key pair
func (m *MultisigManager) GenerateKeyPair() ([]byte, []byte, error) {
	sk, pk, err := m.km.GenerateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("error generating keys: %v", err)
	}

	// Serialize the key pair to bytes
	skBytes, pkBytes, err := m.km.SerializeKeyPair(sk, pk)
	if err != nil {
		return nil, nil, fmt.Errorf("error serializing key pair: %v", err)
	}

	return skBytes, pkBytes, nil
}

// SignMessage signs a message with a given private key
func (m *MultisigManager) SignMessage(message []byte, privateKey []byte, participantID string) ([]byte, *hashtree.HashTreeNode, error) {
	// Deserialize the private key
	sk, _, err := m.km.DeserializeKeyPair(privateKey, nil)
	if err != nil {
		log.Fatalf("Error deserializing key pair: %v", err)
	}

	// Sign the message using the SphincsManager
	sig, merkleRoot, err := m.manager.SignMessage(message, sk)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign message: %v", err)
	}

	// Serialize the signature
	sigBytes, err := m.manager.SerializeSignature(sig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize signature: %v", err)
	}

	// Store the signature and public key of the participant
	m.signatures[participantID] = sigBytes
	m.participantPK[participantID] = privateKey

	// Generate the proof for the signed message
	merkleRootHash := merkleRoot.Hash.Bytes()
	proof, err := sigproof.GenerateSigProof([][]byte{message}, [][]byte{merkleRootHash}, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate proof: %v", err)
	}

	// Store the proof for the participant
	m.proofs[participantID] = proof

	return sigBytes, merkleRoot, nil
}

// VerifySignatures checks if enough signatures have been collected and if the final signature is valid
func (m *MultisigManager) VerifySignatures(message []byte) (bool, error) {
	// Check if we have enough signatures
	if len(m.signatures) < m.threshold {
		return false, fmt.Errorf("not enough signatures, need at least %d", m.threshold)
	}

	// Combine signatures (simple concatenation for example)
	var combinedSignature []byte
	for _, sig := range m.signatures {
		combinedSignature = append(combinedSignature, sig...)
	}

	// Verify the combined signature
	for participantID, sig := range m.signatures {
		publicKey := m.participantPK[participantID]
		deserializedPK, err := m.km.DeserializePublicKey(publicKey)
		if err != nil {
			return false, fmt.Errorf("error deserializing public key: %v", err)
		}

		// Deserialize the signature (sig is expected to be serialized)
		deserializedSig, err := m.manager.DeserializeSignature(sig)
		if err != nil {
			return false, fmt.Errorf("error deserializing signature: %v", err)
		}

		// Verify the signature using the SphincsManager
		isValidSig := m.manager.VerifySignature(message, deserializedSig, deserializedPK, nil) // Merkle root can be passed if necessary
		if !isValidSig {
			return false, fmt.Errorf("signature from participant %s is invalid", participantID)
		}
	}

	return true, nil
}

// SaveRootHash saves the Merkle root hash to a file
func (m *MultisigManager) SaveRootHash(merkleRoot *hashtree.HashTreeNode) error {
	err := hashtree.SaveRootHashToFile(merkleRoot, "root_hashtree/merkle_root_hash.bin")
	if err != nil {
		return fmt.Errorf("failed to save root hash to file: %v", err)
	}
	return nil
}

// GenerateProof generates a proof for the signed message
func (m *MultisigManager) GenerateProof(participantID string) ([]byte, error) {
	proof, exists := m.proofs[participantID]
	if !exists {
		return nil, fmt.Errorf("no proof found for participant %s", participantID)
	}
	return proof, nil
}
