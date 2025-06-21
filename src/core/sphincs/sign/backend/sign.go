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

// StoreTimestampNonce stores a timestamp-nonce pair in LevelDB to prevent signature reuse
// This ensures that a signature cannot be replayed, as the unique pair is recorded
func (sm *SphincsManager) StoreTimestampNonce(timestamp, nonce []byte) error {
	if sm.db == nil {
		return errors.New("LevelDB is not initialized")
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	timestampNonce := append(timestamp, nonce...)
	return sm.db.Put(timestampNonce, []byte("seen"), nil)
}

// CheckTimestampNonce checks if a timestamp-nonce pair exists in LevelDB
// Returns true if the pair exists (indicating reuse), false otherwise
func (sm *SphincsManager) CheckTimestampNonce(timestamp, nonce []byte) (bool, error) {
	if sm.db == nil {
		return false, errors.New("LevelDB is not initialized")
	}
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	timestampNonce := append(timestamp, nonce...)
	_, err := sm.db.Get(timestampNonce, nil)
	if err == nil {
		return true, nil // Pair exists, indicating potential reuse
	}
	if err == leveldb.ErrNotFound {
		return false, nil // Pair does not exist, no reuse detected
	}
	return false, err // Other database error
}

// SignMessage signs a given message using the secret key, including a timestamp and nonce
func (sm *SphincsManager) SignMessage(message []byte, deserializedSK *sphincs.SPHINCS_SK) (*sphincs.SPHINCS_SIG, *hashtree.HashTreeNode, []byte, []byte, error) {
	// Ensure the parameters are initialized
	if sm.parameters == nil || sm.parameters.Params == nil {
		return nil, nil, nil, nil, errors.New("SPHINCSParameters are not initialized")
	}

	// Generate a timestamp
	timestamp := generateTimestamp()

	// Generate a nonce
	nonce, err := generateNonce()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Combine timestamp, nonce, and message
	messageWithTimestampAndNonce := append(timestamp, append(nonce, message...)...)

	// Use SPHINCSParameters for signing
	params := sm.parameters.Params

	// Sign the message with timestamp and nonce
	signature := sphincs.Spx_sign(params, messageWithTimestampAndNonce, deserializedSK)
	if signature == nil {
		return nil, nil, nil, nil, errors.New("failed to sign message")
	}

	// Serialize the generated signature into a byte array
	sigBytes, err := signature.SerializeSignature()
	if err != nil {
		return nil, nil, nil, nil, err
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
		return nil, nil, nil, nil, err
	}

	// Save the leaf nodes (signature parts) into LevelDB in batch mode for performance efficiency
	if sm.db != nil {
		if err := hashtree.SaveLeavesBatchToDB(sm.db, sigParts); err != nil {
			// Return an error if saving the leaves to LevelDB fails
			return nil, nil, nil, nil, err
		}

		// Optionally prune old leaves from the database to prevent the storage from growing indefinitely
		// In this example, we keep the last 5 leaves and prune older ones
		if err := hashtree.PruneOldLeaves(sm.db, 5); err != nil {
			// Return an error if the pruning operation fails
			return nil, nil, nil, nil, err
		}
	}

	// Return the signature, Merkle root, timestamp, and nonce
	return signature, merkleRoot, timestamp, nonce, nil
}

// VerifySignature verifies if a signature is valid for a given message, timestamp, nonce, and public key
func (sm *SphincsManager) VerifySignature(message, timestamp, nonce []byte, sig *sphincs.SPHINCS_SIG, pk *sphincs.SPHINCS_PK, merkleRoot *hashtree.HashTreeNode) bool {
	// Ensure the parameters are initialized
	if sm.parameters == nil || sm.parameters.Params == nil {
		return false
	}

	// Combine timestamp, nonce, and message
	messageWithTimestampAndNonce := append(timestamp, append(nonce, message...)...)

	// Use SPHINCS+ verification
	isValid := sphincs.Spx_verify(sm.parameters.Params, messageWithTimestampAndNonce, sig, pk)
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
