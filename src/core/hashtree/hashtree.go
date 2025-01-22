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

package hashtree

import (
	"fmt"
	"io/ioutil"
	"os"
	"syscall"

	"github.com/holiman/uint256"
	"github.com/sphinx-core/go/src/common"
	"github.com/syndtr/goleveldb/leveldb"
)

// SIPS-0002 https://github.com/sphinx-core/sips/wiki/SIPS-0002

var maxFileSize = 1 << 30 // 1 GiB max file size for memory mapping

// HashTreeNode represents a node in the hash tree
// HashTreeNode represents a node in the hash tree
type HashTreeNode struct {
	Hash   *uint256.Int  `json:"hash"`             // 256-bit Hash of the node's data
	Left   *HashTreeNode `json:"left,omitempty"`   // Left child node
	Right  *HashTreeNode `json:"right,omitempty"`  // Right child node
	Parent *HashTreeNode `json:"parent,omitempty"` // Parent node
}

// NewHashTree creates a new HashTree instance with the given leaves.
func NewHashTree(leaves [][]byte) *HashTree {
	return &HashTree{
		Leaves: leaves,
		Root:   nil,
	}
}

// HashTree represents the Merkle hash tree.
type HashTree struct {
	Leaves [][]byte      // The leaves of the tree
	Root   *HashTreeNode // The root node of the tree
}

// Build constructs the Merkle hash tree from the leaves.
func (tree *HashTree) Build() error {
	tree.Root = BuildHashTree(tree.Leaves)
	return nil
}

// Compute the hash of a given data slice using SphinxHash and return a uint256 value.
func computeUint256(data []byte) *uint256.Int {
	// Compute the hash using SpxHash
	hash := common.SpxHash(data)

	// Convert the resulting hash (32 bytes for 256-bit) to uint256
	return uint256.NewInt(0).SetBytes(hash)
}

// GetSiblingNode returns the sibling of the current node if it exists.
func (node *HashTreeNode) GetSiblingNode(leafIndex int) (*HashTreeNode, error) {
	// If the current node is a leaf, we can check its sibling based on its position
	// This assumes that the leaf nodes are at the bottom level of the tree.
	if node.Left != nil && node.Right != nil {
		if leafIndex%2 == 0 {
			return node.Right, nil // Return right child if the current index is even (left child)
		} else {
			return node.Left, nil // Return left child if the current index is odd (right child)
		}
	}
	return nil, fmt.Errorf("no sibling found for the given node")
}

// BuildHashTree builds a Merkle hash tree from leaf nodes.
// It returns the root node of the hash tree, which is computed by repeatedly
// combining and hashing pairs of leaf nodes and intermediate nodes.
func BuildHashTree(leaves [][]byte) *HashTreeNode {
	// Create an array of hash tree nodes, where each leaf node is hashed.
	nodes := make([]*HashTreeNode, len(leaves))
	for i, leaf := range leaves {
		nodes[i] = &HashTreeNode{Hash: computeUint256(leaf)}
	}

	// Continue building the tree until there is only one node left, the root.
	for len(nodes) > 1 {
		var nextLevel []*HashTreeNode

		// Iterate over the current level two nodes at a time.
		for i := 0; i < len(nodes); i += 2 {
			if i+1 < len(nodes) {
				// Combine the hashes of two sibling nodes (left and right).
				left, right := nodes[i], nodes[i+1]
				// Concatenate the two hashes and compute the hash of the result to create the parent node.
				hash := computeUint256(append(left.Hash.Bytes(), right.Hash.Bytes()...))
				// Create the parent node and set the parent pointers for the children
				parent := &HashTreeNode{Hash: hash, Left: left, Right: right}
				left.Parent = parent
				right.Parent = parent
				// Append the new parent node to the next level, storing references to its children.
				nextLevel = append(nextLevel, parent)
			} else {
				// If there is an odd number of nodes, do not duplicate the last node, carry it over as is.
				// We could either keep it unchanged or mark it as invalid if desired.
				nextLevel = append(nextLevel, nodes[i])
			}
		}

		// Move up one level, using the newly created nodes as the current level.
		nodes = nextLevel
	}

	// Return the single remaining node, which is the root of the hash tree.
	return nodes[0]
}

// Save root hash to file
func SaveRootHashToFile(root *HashTreeNode, filename string) error {
	// Save the root hash (as a byte array) to a file
	return ioutil.WriteFile(filename, root.Hash.Bytes(), 0644)
}

// Load root hash from file
func LoadRootHashFromFile(filename string) ([]byte, error) {
	// Read the root hash from a file and return as a byte array
	return ioutil.ReadFile(filename)
}

// SaveLeavesToDB saves leaf node data to LevelDB.
func SaveLeavesToDB(db *leveldb.DB, leaves [][]byte) error {
	// Iterate over the leaves to be saved to the database
	for i, leaf := range leaves {
		// Generate a unique key for each leaf using a formatted string with its index
		key := fmt.Sprintf("leaf-%d", i)
		// Store the leaf node in LevelDB using the generated key
		err := db.Put([]byte(key), leaf, nil)
		if err != nil {
			return err // Return the error to the caller
		}
	}
	// Return nil to indicate that all leaf nodes were saved successfully
	return nil
}

// Fetch leaf from LevelDB
func FetchLeafFromDB(db *leveldb.DB, key string) ([]byte, error) {
	// Retrieve leaf node from LevelDB using the key
	return db.Get([]byte(key), nil)
}

// PruneOldLeaves removes old leaf nodes from the LevelDB.
func PruneOldLeaves(db *leveldb.DB, numLeaves int) error {
	// Loop over the number of leaves to be deleted
	for i := 0; i < numLeaves; i++ {
		// Generate the key for the leaf node
		key := fmt.Sprintf("leaf-%d", i)
		// Attempt to delete the leaf node by key
		err := db.Delete([]byte(key), nil)
		// If an error occurs, return it, except for the ErrNotFound case
		if err != nil && err != leveldb.ErrNotFound {
			return err
		}
	}
	// Return nil if no errors occurred
	return nil
}

// SaveLeavesBatchToDB performs batch operations for LevelDB to save leaf nodes efficiently.
func SaveLeavesBatchToDB(db *leveldb.DB, leaves [][]byte) error {
	// Create a new batch to accumulate multiple write operations
	batch := new(leveldb.Batch)
	// Iterate over the leaves to be added
	for i, leaf := range leaves {
		// Generate the key for each leaf node
		key := fmt.Sprintf("leaf-%d", i)
		// Add the leaf node to the batch
		batch.Put([]byte(key), leaf)
	}
	// Execute the batch write to LevelDB
	return db.Write(batch, nil)
}

// FetchLeafConcurrent retrieves a leaf node from LevelDB while ensuring safe concurrent access.
func FetchLeafConcurrent(db *leveldb.DB, key string) ([]byte, error) {
	// Retrieve the leaf node from LevelDB
	return db.Get([]byte(key), nil)
}

// setMaxFileSize updates the global maxFileSize variable.
func setMaxFileSize(sizeInGiB int) {
	// Ensure a valid file size is provided
	if sizeInGiB <= 0 {
		fmt.Println("Invalid size. Must be greater than 0.")
		return
	}
	// Convert the size from GiB to bytes
	maxFileSize = sizeInGiB * (1 << 30)
}

// MemoryMapFile maps a file into memory with size checks
func MemoryMapFile(filename string) ([]byte, error) {
	// Open the file for reading
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	// Obtain file descriptor and file stats
	fd := int(file.Fd())
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return nil, fmt.Errorf("error getting file info: %w", err)
	}
	// Check if the file exceeds the max allowed size
	if stat.Size > int64(maxFileSize) {
		return nil, fmt.Errorf("file size exceeds maximum allowed size of %d bytes", maxFileSize)
	}

	// Memory map the file into the memory and return the bytes
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}
	return data, nil
}
