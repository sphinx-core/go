package wots

import "fmt"

// NewKeyManager initializes a KeyManager for Alice at registration
func NewKeyManager(w int) (*KeyManager, error) {
	params := NewWOTSParams(w)
	sk, pk, err := GenerateKeyPair(params)
	if err != nil {
		return nil, fmt.Errorf("failed to generate initial key pair: %v", err)
	}
	return &KeyManager{
		Params:    params,
		CurrentSK: sk,
		CurrentPK: pk,
		NextPK:    nil, // No next public key yet
	}, nil
}

// SignAndRotate signs a transaction and generates a new key pair
func (km *KeyManager) SignAndRotate(message []byte) (*Signature, *PublicKey, *PublicKey, error) {
	// Sign with current private key
	sig, err := km.CurrentSK.Sign(message)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to sign message: %v", err)
	}

	// Store current public key for return
	currentPK := km.CurrentPK

	// Generate new key pair (e.g., skB, pkB after signing with skA)
	newSK, newPK, err := GenerateKeyPair(km.Params)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate new key pair: %v", err)
	}

	// Update KeyManager with new key pair
	km.CurrentSK = newSK
	km.CurrentPK = newPK
	km.NextPK = newPK // Store new public key for next transaction verification

	// Return signature, current public key (for verification), and next public key (for system)
	return sig, currentPK, newPK, nil
}
