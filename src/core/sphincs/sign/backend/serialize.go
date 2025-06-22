package sign

import (
	"errors"

	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
)

// SerializeSignature serializes the signature into a byte slice
func (sm *SphincsManager) SerializeSignature(sig *sphincs.SPHINCS_SIG) ([]byte, error) {
	return sig.SerializeSignature() // Calls the signature's built-in SerializeSignature method
}

// DeserializeSignature deserializes a byte slice into a signature
func (sm *SphincsManager) DeserializeSignature(sigBytes []byte) (*sphincs.SPHINCS_SIG, error) {
	// Ensure the SPHINCSParameters are initialized
	if sm.parameters == nil || sm.parameters.Params == nil {
		return nil, errors.New("SPHINCSParameters are not initialized")
	}

	// Extract the internal *parameters.Parameters from SPHINCSParameters
	sphincsParams := sm.parameters.Params

	// Call the SPHINCS method to deserialize the signature using the extracted params
	return sphincs.DeserializeSignature(sphincsParams, sigBytes)
}
