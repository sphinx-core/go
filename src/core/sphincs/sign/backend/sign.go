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

package sign

import (
	"encoding/hex"
	"errors"

	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
	"github.com/sphinx-core/go/src/core/hashtree"
	params "github.com/sphinx-core/go/src/core/sphincs/config"
	key "github.com/sphinx-core/go/src/core/sphincs/key/backend"
	"github.com/syndtr/goleveldb/leveldb"
)

// SIPS-0002 https://github.com/sphinx-core/sips/wiki/SIPS-0002

// SphincsManager holds a reference to KeyManager
type SphincsManager struct {
	db         *leveldb.DB
	keyManager *key.KeyManager
	parameters *params.SPHINCSParameters // Add SPHINCSParameters
}

// NewSphincsManager creates a new instance of SphincsManager with KeyManager and LevelDB instance
func NewSphincsManager(db *leveldb.DB, keyManager *key.KeyManager, parameters *params.SPHINCSParameters) *SphincsManager {
	if keyManager == nil || parameters == nil || parameters.Params == nil {
		panic("KeyManager or SPHINCSParameters are not properly initialized")
	}
	return &SphincsManager{
		db:         db,
		keyManager: keyManager,
		parameters: parameters,
	}
}

// SignMessage signs a given message using the secret key
// SignMessage signs a given message using the secret key
func (km *SphincsManager) SignMessage(message []byte, deserializedSK *sphincs.SPHINCS_SK) (*sphincs.SPHINCS_SIG, *hashtree.HashTreeNode, error) {
	// Ensure the parameters are initialized
	if km.parameters == nil || km.parameters.Params == nil {
		return nil, nil, errors.New("SPHINCSParameters are not initialized")
	}

	// Use SPHINCSParameters for signing
	params := km.parameters.Params

	// Sign the message
	signature := sphincs.Spx_sign(params, message, deserializedSK)
	if signature == nil {
		return nil, nil, errors.New("failed to sign message")
	}

	// Serialize the generated signature into a byte array
	sigBytes, err := signature.SerializeSignature()
	if err != nil {
		return nil, nil, err
	}

	// Split the serialized signature into parts to build a Merkle tree
	// We divide the signature into 4 equal-sized chunks
	// Assumption if we used params := parameters.MakeSphincsPlusSHAKE256256fRobust
	// So, each chunk will be 8,750 bytes. However, if there's any leftover due to rounding (in case of an odd number),
	// the last chunk will take the remainder. But in this case, the total is divisible by 4, so all four chunks will be exactly 8,750 bytes.
	// First chunk: From byte 0 to 8,749 (8,750 bytes)
	// Second chunk: From byte 8,750 to 17,499 (8,750 bytes)
	// Third chunk: From byte 17,500 to 26,249 (8,750 bytes)
	// Fourth chunk: From byte 26,250 to 34,999 (8,750 bytes)
	// These chunks are then used to construct a Merkle tree, where each chunk becomes a leaf node in the tree.
	chunkSize := len(sigBytes) / 4
	sigParts := make([][]byte, 4) // Initialize an array to hold the 4 signature parts
	for i := 0; i < 4; i++ {
		// Calculate the start and end indices for each part of the signature
		start := i * chunkSize
		end := start + chunkSize
		// For the last chunk, ensure we include any remaining bytes
		if i == 3 {
			end = len(sigBytes)
		}
		// Assign each part of the signature to sigParts
		sigParts[i] = sigBytes[start:end]
	}

	// Efficient Verification:
	// During verification, the signature is reassembled into parts.
	// A Merkle tree is reconstructed, and the root hash is compared with the original
	// Merkle root stored from signing. This ensures the integrity of the signature
	// without loading the entire 35,664 bytes at once.

	// Merkle Root Verification: After the signature verification, the serialized signature
	// is split into four parts, and these parts are used to rebuild a Merkle tree.
	// The hash of the rebuilt Merkle root is then compared with the hash of the provided merkleRoot.
	// If both hashes match, the function returns true, confirming that the signature corresponds
	// to the expected Merkle root.

	// Build a Merkle tree from the signature parts and retrieve the root node
	merkleRoot, err := buildHashTreeFromSignature(sigParts)
	if err != nil {
		// Return an error if the Merkle tree construction fails
		return nil, nil, err
	}

	// Save the leaf nodes (signature parts) into LevelDB in batch mode for performance efficiency
	if err := hashtree.SaveLeavesBatchToDB(km.db, sigParts); err != nil {
		// Return an error if saving the leaves to LevelDB fails
		return nil, nil, err
	}

	// Optionally prune old leaves from the database to prevent the storage from growing indefinitely
	// In this example, we keep the last 5 leaves and prune older ones
	if err := hashtree.PruneOldLeaves(km.db, 5); err != nil {
		// Return an error if the pruning operation fails
		return nil, nil, err
	}

	// Return the generated signature and the root node of the Merkle tree
	return signature, merkleRoot, nil
}

// VerifySignature verifies if a signature is valid for a given message and public key
// Parameters:
// - params: SPHINCS+ parameters used for the signature verification process.
// - message: The original message that was signed.
// - sig: The signature that needs to be verified.
// - pk: The public key used to verify the signature.
// - merkleRoot: The Merkle tree root used for verifying the integrity of the signature.
func (sm *SphincsManager) VerifySignature(message []byte, sig *sphincs.SPHINCS_SIG, pk *sphincs.SPHINCS_PK, merkleRoot *hashtree.HashTreeNode) bool {
	// Ensure the parameters are initialized
	if sm.parameters == nil || sm.parameters.Params == nil {
		return false
	}

	// Use SPHINCS+ verification
	isValid := sphincs.Spx_verify(sm.parameters.Params, message, sig, pk)
	if !isValid {
		return false
	}

	// Serialize the signature into bytes to prepare it for further processing.
	// If serialization fails, return false.
	sigBytes, err := sig.SerializeSignature()
	if err != nil {
		return false
	}

	// Calculate the size of each chunk by dividing the signature into four equal parts.
	// This assumes that the signature can be evenly divided into four parts.
	chunkSize := len(sigBytes) / 4

	// Initialize a slice to hold the four parts of the signature.
	sigParts := make([][]byte, 4)

	// Divide the serialized signature into four parts.
	// Each part is added to the `sigParts` slice.
	for i := 0; i < 4; i++ {
		start := i * chunkSize   // Calculate the starting index for the current part.
		end := start + chunkSize // Calculate the ending index for the current part.
		if i == 3 {              // For the last part, ensure the end index includes any remaining bytes.
			end = len(sigBytes)
		}
		sigParts[i] = sigBytes[start:end] // Add the current part to the `sigParts` slice.
	}

	// Build a Merkle tree from the signature parts to reconstruct the Merkle tree root.
	// This part only constructs the tree without reconstructing the entire signature.
	rebuiltRoot, err := buildHashTreeFromSignature(sigParts)
	if err != nil {
		return false
	}

	// Convert the rebuilt Merkle root hash into a byte slice.
	rebuiltRootHashBytes := rebuiltRoot.Hash.Bytes()

	// Convert the original Merkle root hash into a byte slice.
	merkleRootHashBytes := merkleRoot.Hash.Bytes()

	// Compare the rebuilt root hash with the original Merkle root hash.
	// Convert both to hex strings for comparison.
	// Return true if they match, indicating the signature is valid and its integrity is intact.
	return hex.EncodeToString(rebuiltRootHashBytes) == hex.EncodeToString(merkleRootHashBytes)
}

// Helper functions for serialization and deserialization
// SerializeSignature serializes the signature (sig) into a byte slice
func (sm *SphincsManager) SerializeSignature(sig *sphincs.SPHINCS_SIG) ([]byte, error) {
	return sig.SerializeSignature() // Calls the signature's built-in SerializeSignature method
}

// DeserializeSignature deserializes a byte slice into a signature (sig) using the provided parameters
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

// buildMerkleTreeFromSignature builds the Merkle tree from the signature parts and returns the root node
// buildHashTreeFromSignature constructs a Merkle tree from the provided signature parts
// and returns the root node of the tree.
//
// Parameters:
// - sigParts: A slice of byte slices, where each slice represents a chunk of the signature.
//
// Returns:
// - *hashtree.HashTreeNode: The root node of the constructed Merkle tree.
// - error: An error if tree construction fails.
func buildHashTreeFromSignature(sigParts [][]byte) (*hashtree.HashTreeNode, error) {
	// Create a new Merkle tree instance using the signature parts as leaves
	tree := hashtree.NewHashTree(sigParts)

	// Build the Merkle tree from the provided leaves
	if err := tree.Build(); err != nil {
		// Return an error if the tree construction fails
		return nil, err
	}

	// Return the root node of the constructed tree
	return tree.Root, nil
}
