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

// go/src/core/transaction/merkle.go
package types

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/sphinx-core/go/src/common"
)

// NewMerkleNode creates a new Merkle node
func NewMerkleNode(left, right *MerkleNode, data []byte) *MerkleNode {
	node := &MerkleNode{}

	if left == nil && right == nil {
		// Leaf node: hash the transaction data
		node.Hash = common.SpxHash(data)
		node.IsLeaf = true
	} else {
		// Internal node: hash the concatenation of left and right hashes
		if right != nil {
			// Normal case: both left and right exist
			prevHashes := append(left.Hash, right.Hash...)
			node.Hash = common.SpxHash(prevHashes)
		} else {
			// Odd node case: only left exists, carry it over
			node.Hash = left.Hash
		}
	}

	node.Left = left
	node.Right = right
	return node
}

// NewMerkleTree creates a new Merkle tree from a list of transactions
func NewMerkleTree(txs []*Transaction) *MerkleTree {
	var leaves []*MerkleNode

	// Create leaf nodes from transactions
	for _, tx := range txs {
		txData := tx.SerializeForMerkle()
		leaf := NewMerkleNode(nil, nil, txData)
		leaves = append(leaves, leaf)
	}

	// Handle empty block case
	if len(leaves) == 0 {
		emptyHash := common.SpxHash([]byte{})
		return &MerkleTree{
			Root:   &MerkleNode{Hash: emptyHash, IsLeaf: true},
			Leaves: leaves,
		}
	}

	// Build the tree
	root := buildMerkleTree(leaves)

	return &MerkleTree{
		Root:   root,
		Leaves: leaves,
	}
}

// buildMerkleTree recursively builds the Merkle tree from leaves
// If there is an odd number of nodes, the last node is carried over as is
func buildMerkleTree(nodes []*MerkleNode) *MerkleNode {
	if len(nodes) == 1 {
		return nodes[0]
	}

	var newLevel []*MerkleNode

	// Pair nodes and create parent nodes
	for i := 0; i < len(nodes); i += 2 {
		left := nodes[i]
		var right *MerkleNode

		if i+1 < len(nodes) {
			right = nodes[i+1]
		} else {
			// If there is an odd number of nodes, carry over the last node as is
			// No duplication - just use nil for right node
			right = nil
		}

		parent := NewMerkleNode(left, right, nil)
		newLevel = append(newLevel, parent)
	}

	return buildMerkleTree(newLevel)
}

// GetRoot returns the root hash of the Merkle tree
func (mt *MerkleTree) GetRoot() []byte {
	if mt.Root == nil {
		return common.SpxHash([]byte{})
	}
	return mt.Root.Hash
}

// GetRootHex returns the root hash as a hexadecimal string
func (mt *MerkleTree) GetRootHex() string {
	return hex.EncodeToString(mt.GetRoot())
}

// verifyNode recursively verifies a node's inclusion in the Merkle tree
func (mt *MerkleTree) verifyNode(node, root *MerkleNode) bool {
	if node == nil || root == nil {
		return false
	}

	// Compare by hash value for reliable verification
	if bytes.Equal(node.Hash, root.Hash) {
		return true
	}

	// Recursively check left and right subtrees
	if root.Left != nil && mt.verifyNode(node, root.Left) {
		return true
	}

	if root.Right != nil && mt.verifyNode(node, root.Right) {
		return true
	}

	return false
}

// VerifyTransaction verifies if a transaction is included in the Merkle tree
func (mt *MerkleTree) VerifyTransaction(tx *Transaction) bool {
	txData := tx.SerializeForMerkle()
	txHash := common.SpxHash(txData)

	// Find the leaf node with matching hash
	var targetLeaf *MerkleNode
	for _, leaf := range mt.Leaves {
		if bytes.Equal(leaf.Hash, txHash) {
			targetLeaf = leaf
			break
		}
	}

	if targetLeaf == nil {
		return false
	}

	// Use recursive verification with the root
	return mt.verifyNode(targetLeaf, mt.Root)
}

// CalculateMerkleRoot calculates the Merkle root for a list of transactions
func CalculateMerkleRoot(txs []*Transaction) []byte {
	tree := NewMerkleTree(txs)
	return tree.GetRoot()
}

// SerializeForMerkle serializes a transaction for Merkle tree inclusion
func (tx *Transaction) SerializeForMerkle() []byte {
	// Serialize important transaction data for Merkle tree
	var data []byte

	// Include all relevant transaction fields
	data = append(data, []byte(tx.ID)...)
	data = append(data, []byte(tx.Sender)...)
	data = append(data, []byte(tx.Receiver)...)
	data = append(data, tx.Amount.Bytes()...)
	data = append(data, tx.GasLimit.Bytes()...)
	data = append(data, tx.GasPrice.Bytes()...)

	// Add nonce
	nonceBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceBytes, tx.Nonce)
	data = append(data, nonceBytes...)

	return data
}

// GenerateMerkleProof generates a Merkle proof for a specific transaction
func (mt *MerkleTree) GenerateMerkleProof(tx *Transaction) ([][]byte, error) {
	txData := tx.SerializeForMerkle()
	txHash := common.SpxHash(txData)

	// Find the leaf index
	var leafIndex int = -1
	for i, leaf := range mt.Leaves {
		if string(leaf.Hash) == string(txHash) {
			leafIndex = i
			break
		}
	}

	if leafIndex == -1 {
		return nil, fmt.Errorf("transaction not found in Merkle tree")
	}

	return mt.generateProof(leafIndex, mt.Leaves), nil
}

// generateProof recursively generates the Merkle proof for a leaf at given index
// Updated to handle odd node carry-over
func (mt *MerkleTree) generateProof(index int, nodes []*MerkleNode) [][]byte {
	if len(nodes) == 1 {
		return [][]byte{}
	}

	var proof [][]byte
	var newLevel []*MerkleNode

	for i := 0; i < len(nodes); i += 2 {
		left := nodes[i]
		var right *MerkleNode

		if i+1 < len(nodes) {
			right = nodes[i+1]
		} else {
			// Odd node: no right node, carry over left
			right = nil
		}

		// Create parent node (handles nil right in NewMerkleNode)
		parent := NewMerkleNode(left, right, nil)
		newLevel = append(newLevel, parent)

		// Add to proof if this level contains our target
		if i <= index && (right != nil && index <= i+1 || right == nil && index == i) {
			if index%2 == 0 {
				// Current node is left
				if right != nil {
					proof = append(proof, right.Hash)
				}
				// If right is nil (odd node), no proof element needed for this level
			} else {
				// Current node is right, so left is needed for proof
				proof = append(proof, left.Hash)
			}
		}
	}

	// Calculate new index for next level
	newIndex := index / 2

	// Recursively get proof from next level
	nextProof := mt.generateProof(newIndex, newLevel)
	proof = append(proof, nextProof...)

	return proof
}

// VerifyMerkleProof verifies a Merkle proof for a transaction
// Updated to handle odd node structure
func VerifyMerkleProof(txHash []byte, proof [][]byte, root []byte, leafIndex int, totalLeaves int) bool {
	currentHash := txHash
	currentIndex := leafIndex
	currentTotal := totalLeaves

	for _, proofHash := range proof {
		if currentTotal%2 == 1 && currentIndex == currentTotal-1 {
			// If this was an odd node at the end, it was carried over without pairing
			// In this case, the proof element is from a different branch
			// We need to determine if we should hash with left or right
			if currentIndex%2 == 0 {
				// We were left node, proofHash is from right side if available
				if len(proofHash) > 0 {
					combined := append(currentHash, proofHash...)
					currentHash = common.SpxHash(combined)
				}
				// If no proofHash (nil case), currentHash remains the same
			} else {
				// We were right node, proofHash is from left
				combined := append(proofHash, currentHash...)
				currentHash = common.SpxHash(combined)
			}
		} else {
			// Normal case: pair with sibling
			if currentIndex%2 == 0 {
				// Current is left, proof is right
				combined := append(currentHash, proofHash...)
				currentHash = common.SpxHash(combined)
			} else {
				// Current is right, proof is left
				combined := append(proofHash, currentHash...)
				currentHash = common.SpxHash(combined)
			}
		}

		// Update indices for next level
		currentIndex = currentIndex / 2
		currentTotal = (currentTotal + 1) / 2 // Ceiling division
	}

	return string(currentHash) == string(root)
}

// PrintTree prints the Merkle tree structure for debugging
func (mt *MerkleTree) PrintTree() {
	fmt.Println("Merkle Tree Structure:")
	mt.printNode(mt.Root, 0)
}

// printNode recursively prints a node and its children
func (mt *MerkleTree) printNode(node *MerkleNode, level int) {
	if node == nil {
		return
	}

	indent := ""
	for i := 0; i < level; i++ {
		indent += "  "
	}

	nodeType := "Internal"
	if node.IsLeaf {
		nodeType = "Leaf"
	} else if node.Right == nil && node.Left != nil {
		nodeType = "Carried"
	}

	fmt.Printf("%s%s Node: %s\n", indent, nodeType, hex.EncodeToString(node.Hash)[:8])

	if node.Left != nil {
		mt.printNode(node.Left, level+1)
	}
	if node.Right != nil {
		mt.printNode(node.Right, level+1)
	}
}

// GetTreeHeight returns the height of the Merkle tree
func (mt *MerkleTree) GetTreeHeight() int {
	return mt.calculateHeight(mt.Root)
}

// calculateHeight recursively calculates the height of the tree
func (mt *MerkleTree) calculateHeight(node *MerkleNode) int {
	if node == nil {
		return 0
	}

	leftHeight := mt.calculateHeight(node.Left)
	rightHeight := mt.calculateHeight(node.Right)

	if leftHeight > rightHeight {
		return leftHeight + 1
	}
	return rightHeight + 1
}
