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

// go/src/consensus/signing.go
package consensus

import (
	"crypto"
	"errors"
	"fmt"

	"github.com/holiman/uint256"
	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
	key "github.com/sphinx-core/go/src/core/sphincs/key/backend"
	sign "github.com/sphinx-core/go/src/core/sphincs/sign/backend"
)

// Add this method to register public keys
func (s *SigningService) RegisterPublicKey(nodeID string, publicKey *sphincs.SPHINCS_PK) {
	s.registryMutex.Lock()
	defer s.registryMutex.Unlock()

	if s.publicKeyRegistry == nil {
		s.publicKeyRegistry = make(map[string]*sphincs.SPHINCS_PK)
	}
	s.publicKeyRegistry[nodeID] = publicKey
	fmt.Printf("Registered public key for node %s\n", nodeID)
}

// BytesToUint256 converts a byte slice to uint256.Int
func BytesToUint256(data []byte) *uint256.Int {
	return uint256.NewInt(0).SetBytes(data)
}

// NewSigningService creates a new signing service
func NewSigningService(sphincsManager *sign.SphincsManager, keyManager *key.KeyManager, nodeID string) *SigningService {
	service := &SigningService{
		sphincsManager: sphincsManager,
		keyManager:     keyManager,
		nodeID:         nodeID,
	}

	// Generate keys for this node if not already available
	service.initializeKeys()

	return service
}

// initializeKeys generates or loads keys for this node
func (s *SigningService) initializeKeys() {
	// Generate a new key pair for this node
	skWrapper, pk, err := s.keyManager.GenerateKey()
	if err != nil {
		fmt.Printf("Failed to generate keys: %v\n", err)
		return
	}

	// Convert the wrapper to the actual SPHINCS_SK type
	s.privateKey = &sphincs.SPHINCS_SK{
		SKseed: skWrapper.SKseed,
		SKprf:  skWrapper.SKprf,
		PKseed: skWrapper.PKseed,
		PKroot: skWrapper.PKroot,
	}
	s.publicKey = pk

	fmt.Printf("Initialized keys for node %s\n", s.nodeID)
}

// SignMessage signs a consensus message
// SignMessage signs a consensus message
func (s *SigningService) SignMessage(data []byte) ([]byte, error) {
	if s.sphincsManager == nil || s.privateKey == nil {
		return nil, errors.New("not initialized")
	}

	sig, merkleRoot, timestamp, nonce, err := s.sphincsManager.SignMessage(data, s.privateKey)
	if err != nil {
		return nil, err
	}

	// DEBUG: Log the actual nonce size
	fmt.Printf("DEBUG: Generated nonce size: %d bytes\n", len(nonce))
	fmt.Printf("DEBUG: Generated timestamp size: %d bytes\n", len(timestamp))

	// Serialize just the SPHINCS+ signature (not the entire message)
	sigBytes, err := s.sphincsManager.SerializeSignature(sig)
	if err != nil {
		return nil, err
	}

	// Create a structured signed message
	signedMsg := &SignedMessage{
		Signature:  sigBytes,
		Timestamp:  timestamp,
		Nonce:      nonce,
		MerkleRoot: merkleRoot,
		Data:       data, // Include the original message data
	}

	// Serialize the entire signed message
	return signedMsg.Serialize()
}

// VerifySignature verifies a signature for a message
func (s *SigningService) VerifySignature(signedData []byte, nodeID string) (bool, error) {
	// Deserialize the signed message structure
	signedMsg, err := DeserializeSignedMessage(signedData)
	if err != nil {
		return false, err
	}

	// Deserialize just the SPHINCS+ signature part
	sig, err := s.sphincsManager.DeserializeSignature(signedMsg.Signature)
	if err != nil {
		return false, err
	}

	pk, err := s.getPublicKeyForNode(nodeID)
	if err != nil {
		return false, err
	}

	// Verify using the original message data
	return s.sphincsManager.VerifySignature(
		signedMsg.Data,
		signedMsg.Timestamp,
		signedMsg.Nonce,
		sig,
		pk,
		signedMsg.MerkleRoot,
	), nil
}

// getPublicKeyForNode gets the public key for a node
// Update getPublicKeyForNode to use the registry
func (s *SigningService) getPublicKeyForNode(nodeID string) (*sphincs.SPHINCS_PK, error) {
	s.registryMutex.RLock()
	defer s.registryMutex.RUnlock()

	if publicKey, exists := s.publicKeyRegistry[nodeID]; exists {
		return publicKey, nil
	}

	// Fallback: if it's our own node, return our public key
	if nodeID == s.nodeID && s.publicKey != nil {
		return s.publicKey, nil
	}

	return nil, fmt.Errorf("public key not available for node %s", nodeID)
}

// GenerateMessageHash generates a hash for consensus messages
func (s *SigningService) GenerateMessageHash(messageType string, data []byte) []byte {
	hasher := crypto.SHA256.New()
	hasher.Write([]byte(messageType))
	hasher.Write(data)
	return hasher.Sum(nil)
}

// SignProposal signs a block proposal
// SignProposal signs a block proposal
func (s *SigningService) SignProposal(proposal *Proposal) error {
	data := s.serializeProposalForSigning(proposal)

	signedData, err := s.SignMessage(data)
	if err != nil {
		return err
	}

	proposal.Signature = signedData
	return nil
}

// VerifyProposal verifies a proposal signature
func (s *SigningService) VerifyProposal(proposal *Proposal) (bool, error) {
	return s.VerifySignature(proposal.Signature, proposal.ProposerID)
}

// SignVote signs a vote (prepare or commit)
func (s *SigningService) SignVote(vote *Vote) error {
	data := s.serializeVoteForSigning(vote)

	signature, err := s.SignMessage(data)
	if err != nil {
		return err
	}

	vote.Signature = signature
	return nil
}

// VerifyVote verifies a vote signature
// VerifyVote verifies a vote signature
func (s *SigningService) VerifyVote(vote *Vote) (bool, error) {
	return s.VerifySignature(vote.Signature, vote.VoterID) // CORRECT - 2 arguments
}

// SignTimeout signs a timeout message
func (s *SigningService) SignTimeout(timeout *TimeoutMsg) error {
	data := s.serializeTimeoutForSigning(timeout)

	signature, err := s.SignMessage(data)
	if err != nil {
		return err
	}

	timeout.Signature = signature
	return nil
}

// VerifyTimeout verifies a timeout signature
func (s *SigningService) VerifyTimeout(timeout *TimeoutMsg) (bool, error) {
	return s.VerifySignature(timeout.Signature, timeout.VoterID) // CORRECT - 2 arguments
}

// Serialization methods for signing
func (s *SigningService) serializeProposalForSigning(proposal *Proposal) []byte {
	// Include all critical fields in the signed data
	data := fmt.Sprintf("PROPOSAL:%d:%s:%s:%d",
		proposal.View,
		proposal.Block.GetHash(),
		proposal.ProposerID,
		proposal.Block.GetTimestamp())
	return []byte(data)
}

func (s *SigningService) serializeVoteForSigning(vote *Vote) []byte {
	data := fmt.Sprintf("VOTE:%d:%s:%s",
		vote.View,
		vote.BlockHash,
		vote.VoterID)
	return []byte(data)
}

func (s *SigningService) serializeTimeoutForSigning(timeout *TimeoutMsg) []byte {
	data := fmt.Sprintf("TIMEOUT:%d:%s:%d",
		timeout.View,
		timeout.VoterID,
		timeout.Timestamp)
	return []byte(data)
}

// GetPublicKey returns the public key for this node
func (s *SigningService) GetPublicKey() ([]byte, error) {
	if s.publicKey == nil {
		return nil, fmt.Errorf("public key not available")
	}

	// Serialize the public key
	return s.publicKey.SerializePK()
}

// GetPublicKeyObject returns the public key object for this node
func (s *SigningService) GetPublicKeyObject() *sphincs.SPHINCS_PK {
	return s.publicKey
}
