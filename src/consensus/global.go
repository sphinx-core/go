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

// go/src/consensus/global.go
package consensus

import "time"

// Configuration
const (
	BATCH_SIZE     = 10000
	BASE_TIMEOUT   = 150 * time.Millisecond
	FAST_TIMEOUT   = 80 * time.Millisecond
	PIPELINE_DEPTH = 3
)

// Node role constants defining different types of nodes in the network
const (
	RoleValidator NodeRole = iota // Validator nodes participate in consensus voting
	RoleObserver                  // Observer nodes can read but not participate in consensus
	RoleBootnode                  // Bootnodes help other nodes discover the network
)

// Node status constants representing the current state of a node
const (
	NodeStatusActive   NodeStatus = iota // Node is active and participating
	NodeStatusInactive                   // Node is inactive or disconnected
	NodeStatusSyncing                    // Node is synchronizing with the network
)

// Consensus phase constants representing the current state of PBFT consensus
const (
	PhaseIdle         ConsensusPhase = iota // No active consensus round
	PhasePrePrepared                        // Received proposal but not yet prepared
	PhasePrepared                           // Received enough prepare votes to proceed
	PhaseCommitted                          // Received enough commit votes to finalize
	PhaseViewChanging                       // In the process of changing consensus view
)
