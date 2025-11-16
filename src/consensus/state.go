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

// go/src/consensus/state.go
package consensus

import (
	"time"

	logger "github.com/sphinx-core/go/src/log"
)

// NewConsensusState creates a new consensus state instance with initial values
// Initializes the consensus state to starting conditions:
// - View 0: Starting view number
// - Height 0: Starting block height
// - PhaseIdle: No active consensus round
// Returns a new ConsensusState instance ready for use
func NewConsensusState() *ConsensusState {
	return &ConsensusState{
		currentView:   0,         // Start at view 0
		currentHeight: 0,         // Start at height 0
		phase:         PhaseIdle, // No active consensus round
	}
}

// ResetForNewViewEnhanced provides safer view change with leader election
func (cs *ConsensusState) ResetForNewViewEnhanced(view uint64, validators []string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	cs.currentView = view
	cs.phase = PhaseIdle
	cs.preparedBlock = nil
	cs.preparedView = 0
	cs.lastViewChange = time.Now()

	// Note: lockedBlock is preserved for safety across view changes
	logger.Info("View change completed: view=%d, validators=%d", view, len(validators))
}

// CanChangeView checks if enough time has passed since last view change
func (cs *ConsensusState) CanChangeView() bool {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return time.Since(cs.lastViewChange) > 2*time.Second
}

// GetCurrentView returns the current consensus view number
// View represents the current consensus round or epoch
// Uses read lock for thread-safe access to shared state
// Returns the current view number (uint64)
func (cs *ConsensusState) GetCurrentView() uint64 {
	cs.mu.RLock()         // Acquire read lock for concurrent access
	defer cs.mu.RUnlock() // Ensure lock is released when function exits
	return cs.currentView // Return current view number
}

// SetCurrentView updates the current consensus view number
// View changes occur during view change protocol or when progressing to new rounds
// Uses write lock for thread-safe modification of shared state
// view: The new view number to set
func (cs *ConsensusState) SetCurrentView(view uint64) {
	cs.mu.Lock()          // Acquire write lock for exclusive access
	defer cs.mu.Unlock()  // Ensure lock is released when function exits
	cs.currentView = view // Update current view number
}

// GetCurrentHeight returns the current blockchain height
// Height represents the number of blocks committed to the chain
// Uses read lock for thread-safe access to shared state
// Returns the current block height (uint64)
func (cs *ConsensusState) GetCurrentHeight() uint64 {
	cs.mu.RLock()           // Acquire read lock for concurrent access
	defer cs.mu.RUnlock()   // Ensure lock is released when function exits
	return cs.currentHeight // Return current block height
}

// SetCurrentHeight updates the current blockchain height
// Height increases when new blocks are successfully committed
// Uses write lock for thread-safe modification of shared state
// height: The new block height to set
func (cs *ConsensusState) SetCurrentHeight(height uint64) {
	cs.mu.Lock()              // Acquire write lock for exclusive access
	defer cs.mu.Unlock()      // Ensure lock is released when function exits
	cs.currentHeight = height // Update current block height
}

// GetPhase returns the current consensus phase
// Phase indicates the progress in the PBFT consensus protocol:
// - PhaseIdle: No active consensus round
// - PhasePrePrepared: Received proposal but not yet prepared
// - PhasePrepared: Received enough prepare votes to proceed
// - PhaseCommitted: Received enough commit votes to finalize
// - PhaseViewChanging: In the process of changing consensus view
// Uses read lock for thread-safe access to shared state
// Returns the current consensus phase
func (cs *ConsensusState) GetPhase() ConsensusPhase {
	cs.mu.RLock()         // Acquire read lock for concurrent access
	defer cs.mu.RUnlock() // Ensure lock is released when function exits
	return cs.phase       // Return current consensus phase
}

// SetPhase updates the current consensus phase
// Phase transitions occur as the consensus protocol progresses through PBFT stages
// Uses write lock for thread-safe modification of shared state
// phase: The new consensus phase to set
func (cs *ConsensusState) SetPhase(phase ConsensusPhase) {
	cs.mu.Lock()         // Acquire write lock for exclusive access
	defer cs.mu.Unlock() // Ensure lock is released when function exits
	cs.phase = phase     // Update current consensus phase
}

// GetLockedBlock returns the currently locked block
// Locked block is the block that has passed the prepare phase and is locked in
// Provides safety by preventing different blocks from being committed at same height
// Uses read lock for thread-safe access to shared state
// Returns the currently locked block (may be nil if no block is locked)
func (cs *ConsensusState) GetLockedBlock() Block {
	cs.mu.RLock()         // Acquire read lock for concurrent access
	defer cs.mu.RUnlock() // Ensure lock is released when function exits
	return cs.lockedBlock // Return currently locked block
}

// SetLockedBlock sets the locked block for the current consensus round
// A block becomes locked after receiving sufficient prepare votes (PhasePrepared)
// Locked block cannot be changed until the current round completes or times out
// Uses write lock for thread-safe modification of shared state
// block: The block to set as the locked block
func (cs *ConsensusState) SetLockedBlock(block Block) {
	cs.mu.Lock()           // Acquire write lock for exclusive access
	defer cs.mu.Unlock()   // Ensure lock is released when function exits
	cs.lockedBlock = block // Set the locked block
}

// GetPreparedBlock returns the currently prepared block
// Prepared block is the block that has been received in a proposal but not yet locked
// This is the candidate block for the current consensus round
// Uses read lock for thread-safe access to shared state
// Returns the currently prepared block (may be nil if no block is prepared)
func (cs *ConsensusState) GetPreparedBlock() Block {
	cs.mu.RLock()           // Acquire read lock for concurrent access
	defer cs.mu.RUnlock()   // Ensure lock is released when function exits
	return cs.preparedBlock // Return currently prepared block
}

// SetPreparedBlock sets the prepared block and its associated view
// A block becomes prepared when received from a valid proposal in the current view
// This starts the prepare phase where validators vote on the block
// Uses write lock for thread-safe modification of shared state
// block: The block to set as prepared
// view: The view number in which this block was prepared
func (cs *ConsensusState) SetPreparedBlock(block Block, view uint64) {
	cs.mu.Lock()             // Acquire write lock for exclusive access
	defer cs.mu.Unlock()     // Ensure lock is released when function exits
	cs.preparedBlock = block // Set the prepared block
	cs.preparedView = view   // Set the view in which block was prepared
}

// ResetForNewView resets consensus state for a new view while preserving safety
// Called during view change protocol to prepare for a new consensus round
// Resets most state but preserves lockedBlock for safety across view changes
// This ensures the "locked block" safety property is maintained
// Uses write lock for thread-safe modification of shared state
// view: The new view number to transition to
func (cs *ConsensusState) ResetForNewView(view uint64) {
	cs.mu.Lock()         // Acquire write lock for exclusive access
	defer cs.mu.Unlock() // Ensure lock is released when function exits

	cs.currentView = view  // Update to new view number
	cs.phase = PhaseIdle   // Reset to idle phase for new round
	cs.preparedBlock = nil // Clear prepared block (new proposal expected)
	cs.preparedView = 0    // Reset prepared view

	// Note: We don't reset lockedBlock as it provides safety across views
	// The locked block ensures that if a block was committed in a previous view,
	// we don't accidentally commit a different block at the same height
	// This maintains the PBFT safety property during view changes
}
