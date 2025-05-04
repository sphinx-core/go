package wots

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math"
)

// GenerateKeyPair generates a WOTS private-public key pair
func GenerateKeyPair(params WOTSParams) (*PrivateKey, *PublicKey, error) {
	privKey := make([][]byte, params.T)
	for i := 0; i < params.T; i++ {
		privKey[i] = make([]byte, params.N)
		_, err := rand.Read(privKey[i])
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate random private key: %v", err)
		}
	}

	pubKey := make([][]byte, params.T)
	maxHashes := int(math.Pow(2, float64(params.W))) - 1
	for i := 0; i < params.T; i++ {
		pubKey[i] = make([]byte, params.N)
		copy(pubKey[i], privKey[i])
		for j := 0; j < maxHashes; j++ {
			hash := sha256.Sum256(pubKey[i])
			copy(pubKey[i], hash[:])
		}
	}

	return &PrivateKey{Params: params, Key: privKey},
		&PublicKey{Params: params, Key: pubKey},
		nil
}

// Sign generates a WOTS signature for a message
func (sk *PrivateKey) Sign(message []byte) (*Signature, error) {
	msgHash := sha256.Sum256(message)
	params := sk.Params
	logW := int(math.Log2(float64(params.W)))

	baseW := make([]int, params.T1)
	for i := 0; i < params.T1; i++ {
		startBit := i * logW
		startByte := startBit / 8
		bitOffset := startBit % 8
		var value int
		if bitOffset+logW <= 8 {
			value = int((msgHash[startByte] >> (8 - bitOffset - logW)) & (1<<logW - 1))
		} else {
			value = int((msgHash[startByte] << bitOffset) | (msgHash[startByte+1] >> (16 - bitOffset - logW)))
			value &= (1 << logW) - 1
		}
		baseW[i] = value
	}

	checksum := 0
	maxValue := int(math.Pow(2, float64(params.W))) - 1
	for _, v := range baseW {
		checksum += maxValue - v
	}

	checksumBaseW := make([]int, params.T2)
	for i := params.T2 - 1; i >= 0; i-- {
		checksumBaseW[i] = checksum & (int(math.Pow(2, float64(logW))) - 1)
		checksum >>= logW
	}

	combined := append(baseW, checksumBaseW...)

	sig := make([][]byte, params.T)
	for i := 0; i < params.T; i++ {
		sig[i] = make([]byte, params.N)
		copy(sig[i], sk.Key[i])
		for j := 0; j < combined[i]; j++ {
			hash := sha256.Sum256(sig[i])
			copy(sig[i], hash[:])
		}
	}

	return &Signature{Params: params, Sig: sig}, nil
}

// Verify checks a WOTS signature
func (pk *PublicKey) Verify(message []byte, sig *Signature) (bool, error) {
	if sig.Params != pk.Params {
		return false, fmt.Errorf("signature parameters do not match public key parameters")
	}

	msgHash := sha256.Sum256(message)
	params := pk.Params
	logW := int(math.Log2(float64(params.W)))

	baseW := make([]int, params.T1)
	for i := 0; i < params.T1; i++ {
		startBit := i * logW
		startByte := startBit / 8
		bitOffset := startBit % 8
		var value int
		if bitOffset+logW <= 8 {
			value = int((msgHash[startByte] >> (8 - bitOffset - logW)) & (1<<logW - 1))
		} else {
			value = int((msgHash[startByte] << bitOffset) | (msgHash[startByte+1] >> (16 - bitOffset - logW)))
			value &= (1 << logW) - 1
		}
		baseW[i] = value
	}

	checksum := 0
	maxValue := int(math.Pow(2, float64(params.W))) - 1
	for _, v := range baseW {
		checksum += maxValue - v
	}

	checksumBaseW := make([]int, params.T2)
	for i := params.T2 - 1; i >= 0; i-- {
		checksumBaseW[i] = checksum & (int(math.Pow(2, float64(logW))) - 1)
		checksum >>= logW
	}

	combined := append(baseW, checksumBaseW...)

	for i := 0; i < params.T; i++ {
		numHashes := maxValue - combined[i]
		current := make([]byte, params.N)
		copy(current, sig.Sig[i])
		for j := 0; j < numHashes; j++ {
			hash := sha256.Sum256(current)
			copy(current, hash[:])
		}
		for j := 0; j < params.N; j++ {
			if current[j] != pk.Key[i][j] {
				return false, nil
			}
		}
	}

	return true, nil
}
