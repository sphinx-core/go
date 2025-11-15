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

// go/src/consensus/quorum.go
package consensus

import (
	"math"
)

// NewQuorumVerifier creates a new quorum verifier instance
// totalNodes: Total number of nodes in the network
// faultyNodes: Number of faulty (Byzantine) nodes to tolerate
// quorumFraction: Fraction of nodes required for quorum (typically 2/3 for BFT)
// Returns a configured QuorumVerifier instance
func NewQuorumVerifier(totalNodes, faultyNodes int, quorumFraction float64) *QuorumVerifier {
	return &QuorumVerifier{
		totalNodes:     totalNodes,
		faultyNodes:    faultyNodes,
		quorumFraction: quorumFraction,
	}
}

// VerifySafety checks if the system can guarantee safety with current parameters
// Safety ensures that two different blocks cannot be committed at the same height
// For Byzantine Fault Tolerance (BFT), requires:
// - Quorum fraction >= 2/3
// - Faulty nodes < total nodes / 3
// Returns true if safety can be guaranteed with current configuration
func (qv *QuorumVerifier) VerifySafety() bool {
	// Check if quorum fraction meets BFT requirement (at least 2/3)
	meetsQuorumRequirement := qv.quorumFraction >= 2.0/3.0

	// Check if faulty nodes are within BFT tolerance limit (less than 1/3)
	meetsFaultTolerance := qv.faultyNodes < qv.totalNodes/3

	// Both conditions must be true for safety guarantee
	return meetsQuorumRequirement && meetsFaultTolerance
}

// VerifyQuorumIntersection verifies the quorum intersection property
// Quorum intersection ensures any two quorums have at least one honest node in common
// This prevents network splits and ensures consensus consistency
// Formula: (2Q - 1) * totalNodes > faultyNodes
// Where Q is the quorum fraction
// Returns true if quorum intersection property is satisfied
func (qv *QuorumVerifier) VerifyQuorumIntersection() bool {
	Q := qv.quorumFraction
	// Calculate the intersection size between any two quorums
	intersection := (2*Q - 1) * float64(qv.totalNodes)
	// Intersection must be larger than number of faulty nodes to ensure at least one honest node
	return intersection > float64(qv.faultyNodes)
}

// CalculateMinQuorumSize calculates minimum quorum size needed
// Quorum size is the minimum number of nodes required to reach consensus
// Calculated as: ceil(totalNodes * quorumFraction)
// Returns the minimum quorum size (at least 1)
func (qv *QuorumVerifier) CalculateMinQuorumSize() int {
	// Calculate minimum quorum size using ceiling to ensure we have enough nodes
	minSize := int(math.Ceil(float64(qv.totalNodes) * qv.quorumFraction))
	// Ensure we have at least 1 node in quorum (edge case for very small networks)
	if minSize < 1 {
		return 1
	}
	return minSize
}

// CalculateOptimalQuorumFraction calculates the optimal Q for given fault tolerance
// This calculates the minimum quorum fraction needed to tolerate given faulty nodes
// Formula: (2f + 1) / N where f is faulty nodes, N is total nodes
// For BFT systems, minimum is 2/3 to ensure safety and liveness
// faultyNodes: Number of faulty nodes to tolerate
// totalNodes: Total number of nodes in the network
// Returns the optimal quorum fraction (never less than 2/3)
func CalculateOptimalQuorumFraction(faultyNodes, totalNodes int) float64 {
	// Handle edge case where there are no nodes
	if totalNodes == 0 {
		return 2.0 / 3.0 // Return default BFT fraction
	}

	// Calculate theoretical minimum quorum fraction: (2f + 1)/N
	calculated := float64(2*faultyNodes+1) / float64(totalNodes)

	// Ensure we meet BFT minimum requirement of 2/3
	if calculated < 2.0/3.0 {
		return 2.0 / 3.0
	}

	return calculated
}

// NewQuorumCalculator creates a new quorum calculator instance
// quorumFraction: The fraction of nodes required for quorum
// Returns a configured QuorumCalculator instance
func NewQuorumCalculator(quorumFraction float64) *QuorumCalculator {
	return &QuorumCalculator{
		quorumFraction: quorumFraction,
	}
}

// VerifyQuorumIntersection verifies the quorum intersection property
// This is the same verification as in QuorumVerifier but with explicit parameters
// totalNodes: Total number of nodes in the network
// faultyNodes: Number of faulty (Byzantine) nodes
// Returns true if quorum intersection property is satisfied
func (qc *QuorumCalculator) VerifyQuorumIntersection(totalNodes, faultyNodes int) bool {
	Q := qc.quorumFraction
	// Calculate intersection size: (2Q - 1) * totalNodes
	intersection := (2*Q - 1) * float64(totalNodes)
	// Intersection must exceed faulty nodes to ensure consensus consistency
	return intersection > float64(faultyNodes)
}

// CalculateMaxFaulty calculates maximum faulty nodes tolerated
// This determines how many Byzantine nodes the system can handle while maintaining safety
// Formula: floor((1 - Q) * totalNodes)
// Where Q is the quorum fraction
// totalNodes: Total number of nodes in the network
// Returns maximum number of faulty nodes that can be tolerated
func (qc *QuorumCalculator) CalculateMaxFaulty(totalNodes int) int {
	// Calculate maximum faulty nodes: (1 - Q) * totalNodes
	maxFaulty := int((1 - qc.quorumFraction) * float64(totalNodes))

	// Ensure non-negative result
	if maxFaulty < 0 {
		return 0
	}

	return maxFaulty
}
