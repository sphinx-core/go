// go/ src/ core/
package zk

import (
	"encoding/hex"
	"fmt"

	sphincs "github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
	params "github.com/sphinx-core/go/src/core/sphincs/config"
	key "github.com/sphinx-core/go/src/core/sphincs/key/backend"
)

// NewSignWrapper initializes a new SignWrapper.
func NewSigner() *Signer {
	return &Signer{}
}

// SignMessage signs a message using the provided SPHINCS+ parameters and secret key.
func (sw *Signer) SignMessage(sphincsParams *params.SPHINCSParameters, message []byte, sk *key.SPHINCS_SK) (*sphincs.SPHINCS_SIG, error) {
	sphincsSK := &sphincs.SPHINCS_SK{
		SKseed: sk.SKseed,
		SKprf:  sk.SKprf,
		PKseed: sk.PKseed,
		PKroot: sk.PKroot,
	}
	sig := sphincs.Spx_sign(sphincsParams.Params, message, sphincsSK)
	if sig == nil {
		return nil, fmt.Errorf("failed to sign message: signature is nil")
	}
	return sig, nil
}

// VerifySignature verifies a SPHINCS+ signature for a given message and public key.
func (sw *Signer) VerifySignature(sphincsParams *params.SPHINCSParameters, message []byte, sig *sphincs.SPHINCS_SIG, pk *sphincs.SPHINCS_PK) (bool, error) {
	valid := sphincs.Spx_verify(sphincsParams.Params, message, sig, pk)
	return valid, nil
}

// SerializeSignature serializes a SPHINCS+ signature and returns its hex representation and size.
func (sw *Signer) SerializeSignature(sig *sphincs.SPHINCS_SIG) (sigHex string, sigSize float64, err error) {
	sigBytes, err := sig.SerializeSignature()
	if err != nil {
		return "", 0, fmt.Errorf("failed to serialize signature: %v", err)
	}
	return hex.EncodeToString(sigBytes), float64(len(sigBytes)) / 1024.0, nil
}

// DeserializeSignature deserializes a SPHINCS+ signature from bytes.
func (sw *Signer) DeserializeSignature(sphincsParams *params.SPHINCSParameters, sigBytes []byte) (*sphincs.SPHINCS_SIG, error) {
	sig, err := sphincs.DeserializeSignature(sphincsParams.Params, sigBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize signature: %v", err)
	}
	return sig, nil
}
