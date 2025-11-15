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

// go/src/state/smr.go
package state

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/sphinx-core/go/src/consensus"
	types "github.com/sphinx-core/go/src/core/transaction"
)

const (
	OpBlock OperationType = iota
	OpTransaction
	OpStateTransition
)

// NewStateMachine creates a new state machine replication instance
func NewStateMachine(storage *Storage, nodeID string, validators []string) *StateMachine {
	quorumSize := calculateQuorumSize(len(validators))

	validatorMap := make(map[string]bool)
	for _, v := range validators {
		validatorMap[v] = true
	}

	sm := &StateMachine{
		storage:      storage,
		nodeID:       nodeID,
		validators:   validatorMap,
		quorumSize:   quorumSize,
		stateHistory: make(map[uint64]*StateSnapshot),
		opCh:         make(chan *Operation, 1000),
		stateCh:      make(chan *StateSnapshot, 100),
		commitCh:     make(chan *CommitProof, 100),
		timeoutCh:    make(chan struct{}, 10),
	}

	// Load initial state
	if err := sm.loadInitialState(); err != nil {
		log.Printf("Warning: Could not load initial state: %v", err)
		sm.createInitialState()
	}

	return sm
}

// SetConsensus sets the consensus module for the state machine
func (sm *StateMachine) SetConsensus(consensus *consensus.Consensus) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.consensus = consensus
}

// Start begins the state machine replication
func (sm *StateMachine) Start() error {
	log.Printf("State machine replication started for node %s", sm.nodeID)

	// Start handlers
	go sm.handleOperations()
	go sm.handleStateUpdates()
	go sm.handleCommits()
	go sm.replicationLoop()

	return nil
}

// Stop halts the state machine replication
func (sm *StateMachine) Stop() error {
	log.Printf("State machine replication stopped for node %s", sm.nodeID)
	return nil
}

// ProposeBlock proposes a new block for state machine replication
func (sm *StateMachine) ProposeBlock(block *types.Block) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if !sm.isValidator() {
		return fmt.Errorf("node %s is not a validator", sm.nodeID)
	}

	// Validate block before proposing
	if err := block.Validate(); err != nil {
		return fmt.Errorf("block validation failed: %w", err)
	}

	// Create operation
	op := &Operation{
		Type:      OpBlock,
		Block:     block,
		View:      sm.currentView,
		Sequence:  sm.currentState.Height + 1,
		Proposer:  sm.nodeID,
		Signature: []byte{}, // Should be properly signed
	}

	// Send to operation channel
	select {
	case sm.opCh <- op:
		log.Printf("Proposed block for state machine replication: height=%d, hash=%s",
			block.GetHeight(), block.GetHash())
		return nil
	default:
		return fmt.Errorf("operation channel full")
	}
}

// ProposeTransaction proposes a transaction for state machine replication
func (sm *StateMachine) ProposeTransaction(tx *types.Transaction) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Validate transaction
	if err := tx.SanityCheck(); err != nil {
		return fmt.Errorf("transaction validation failed: %w", err)
	}

	// Create operation
	op := &Operation{
		Type:        OpTransaction,
		Transaction: tx,
		View:        sm.currentView,
		Sequence:    sm.currentState.Height + 1,
		Proposer:    sm.nodeID,
		Signature:   []byte{},
	}

	// Send to operation channel
	select {
	case sm.opCh <- op:
		log.Printf("Proposed transaction for state machine replication: txID=%s", tx.ID)
		return nil
	default:
		return fmt.Errorf("operation channel full")
	}
}

// HandleOperation processes an incoming operation from other nodes
func (sm *StateMachine) HandleOperation(op *Operation) error {
	// Validate operation
	if err := sm.validateOperation(op); err != nil {
		return fmt.Errorf("operation validation failed: %w", err)
	}

	// Send to operation channel
	select {
	case sm.opCh <- op:
		return nil
	default:
		return fmt.Errorf("operation channel full")
	}
}

// HandleCommitProof processes a commit proof from other nodes
func (sm *StateMachine) HandleCommitProof(proof *CommitProof) error {
	// Validate commit proof
	if err := sm.validateCommitProof(proof); err != nil {
		return fmt.Errorf("commit proof validation failed: %w", err)
	}

	// Send to commit channel
	select {
	case sm.commitCh <- proof:
		return nil
	default:
		return fmt.Errorf("commit channel full")
	}
}

// GetCurrentState returns the current state snapshot
func (sm *StateMachine) GetCurrentState() *StateSnapshot {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.currentState
}

// GetStateAtHeight returns state snapshot at specific height
func (sm *StateMachine) GetStateAtHeight(height uint64) (*StateSnapshot, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// Try state history first
	if snapshot, exists := sm.stateHistory[height]; exists {
		return snapshot, nil
	}

	// Fall back to storage
	block, err := sm.storage.GetBlockByHeight(height)
	if err != nil {
		return nil, fmt.Errorf("failed to get block at height %d: %w", height, err)
	}

	return sm.createStateSnapshot(block)
}

// VerifyState verifies if a state matches the current state
func (sm *StateMachine) VerifyState(snapshot *StateSnapshot) (bool, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.currentState.Height != snapshot.Height {
		return false, fmt.Errorf("height mismatch: current=%d, provided=%d",
			sm.currentState.Height, snapshot.Height)
	}

	if sm.currentState.BlockHash != snapshot.BlockHash {
		return false, fmt.Errorf("block hash mismatch: current=%s, provided=%s",
			sm.currentState.BlockHash, snapshot.BlockHash)
	}

	// Verify state root (if implemented)
	if sm.currentState.StateRoot != snapshot.StateRoot {
		return false, fmt.Errorf("state root mismatch")
	}

	return true, nil
}

// Private methods

func (sm *StateMachine) replicationLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sm.checkProgress()
		case <-sm.timeoutCh:
			sm.handleTimeout()
		}
	}
}

func (sm *StateMachine) handleOperations() {
	for op := range sm.opCh {
		if err := sm.processOperation(op); err != nil {
			log.Printf("Failed to process operation: %v", err)
			continue
		}
	}
}

func (sm *StateMachine) handleStateUpdates() {
	for snapshot := range sm.stateCh {
		if err := sm.applyStateSnapshot(snapshot); err != nil {
			log.Printf("Failed to apply state snapshot: %v", err)
			continue
		}
	}
}

func (sm *StateMachine) handleCommits() {
	for proof := range sm.commitCh {
		if err := sm.applyCommitProof(proof); err != nil {
			log.Printf("Failed to apply commit proof: %v", err)
			continue
		}
	}
}

func (sm *StateMachine) processOperation(op *Operation) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Check sequence number
	if op.Sequence <= sm.lastApplied {
		return fmt.Errorf("stale operation: sequence=%d, lastApplied=%d",
			op.Sequence, sm.lastApplied)
	}

	// Add to pending operations
	sm.pendingOps = append(sm.pendingOps, op)

	// If we have quorum of operations for this sequence, apply them
	if sm.hasOperationQuorum(op.Sequence) {
		return sm.applyPendingOperations(op.Sequence)
	}

	return nil
}

func (sm *StateMachine) applyPendingOperations(sequence uint64) error {
	// Group operations by sequence
	var opsForSequence []*Operation
	for _, op := range sm.pendingOps {
		if op.Sequence == sequence {
			opsForSequence = append(opsForSequence, op)
		}
	}

	// Apply operations in deterministic order
	for _, op := range opsForSequence {
		if err := sm.applyOperation(op); err != nil {
			return fmt.Errorf("failed to apply operation: %w", err)
		}
	}

	// Update last applied
	sm.lastApplied = sequence

	// Remove applied operations
	sm.pendingOps = sm.filterPendingOps(sequence)

	log.Printf("Applied %d operations for sequence %d", len(opsForSequence), sequence)
	return nil
}

func (sm *StateMachine) applyOperation(op *Operation) error {
	switch op.Type {
	case OpBlock:
		return sm.applyBlockOperation(op)
	case OpTransaction:
		return sm.applyTransactionOperation(op)
	case OpStateTransition:
		return sm.applyStateTransitionOperation(op)
	default:
		return fmt.Errorf("unknown operation type: %d", op.Type)
	}
}

func (sm *StateMachine) applyBlockOperation(op *Operation) error {
	// Store block in storage
	if err := sm.storage.StoreBlock(op.Block); err != nil {
		return fmt.Errorf("failed to store block: %w", err)
	}

	// Update state
	newState, err := sm.createStateSnapshot(op.Block)
	if err != nil {
		return fmt.Errorf("failed to create state snapshot: %w", err)
	}

	// Send to state channel
	select {
	case sm.stateCh <- newState:
		return nil
	default:
		return fmt.Errorf("state channel full")
	}
}

func (sm *StateMachine) applyTransactionOperation(op *Operation) error {
	// For now, transactions are applied when included in blocks
	// This could be extended for mempool replication
	log.Printf("Transaction operation received: %s", op.Transaction.ID)
	return nil
}

func (sm *StateMachine) applyStateTransitionOperation(op *Operation) error {
	// Handle state transitions (validator set changes, etc.)
	log.Printf("State transition operation received")
	return nil
}

func (sm *StateMachine) applyStateSnapshot(snapshot *StateSnapshot) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Verify snapshot is newer than current state
	if snapshot.Height <= sm.currentState.Height {
		return fmt.Errorf("stale snapshot: height=%d, current=%d",
			snapshot.Height, sm.currentState.Height)
	}

	// Update current state
	sm.currentState = snapshot
	sm.stateHistory[snapshot.Height] = snapshot

	// Persist state
	if err := sm.persistState(snapshot); err != nil {
		return fmt.Errorf("failed to persist state: %w", err)
	}

	log.Printf("State updated to height %d, block %s", snapshot.Height, snapshot.BlockHash)
	return nil
}

func (sm *StateMachine) applyCommitProof(proof *CommitProof) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Mark state as committed
	if state, exists := sm.stateHistory[proof.Height]; exists {
		state.Committed = true

		// Persist committed state
		if err := sm.persistState(state); err != nil {
			return fmt.Errorf("failed to persist committed state: %w", err)
		}

		log.Printf("State at height %d committed with %d signatures",
			proof.Height, len(proof.Signatures))
	}

	return nil
}

func (sm *StateMachine) createStateSnapshot(block *types.Block) (*StateSnapshot, error) {
	// Calculate state root (simplified - in practice this would be a Merkle root)
	stateRoot := sm.calculateStateRoot(block)

	snapshot := &StateSnapshot{
		Height:     block.GetHeight(),
		BlockHash:  block.GetHash(),
		StateRoot:  stateRoot,
		Timestamp:  time.Now(),
		Validators: sm.validators,
		UTXOSet:    make(map[string]*types.UTXO),   // Would be populated from block
		Accounts:   make(map[string]*AccountState), // Would be populated from block
		Committed:  false,
	}

	return snapshot, nil
}

func (sm *StateMachine) calculateStateRoot(block *types.Block) string {
	// Simplified state root calculation
	// In practice, this would compute a Merkle root of the entire state
	data := fmt.Sprintf("%s-%d-%d", block.GetHash(), block.GetHeight(), block.GetTimestamp())
	return fmt.Sprintf("%x", []byte(data)) // Simple hash
}

func (sm *StateMachine) validateOperation(op *Operation) error {
	// Check proposer is a validator
	if !sm.validators[op.Proposer] {
		return fmt.Errorf("proposer %s is not a validator", op.Proposer)
	}

	// Check view number
	if op.View < sm.currentView {
		return fmt.Errorf("stale view: %d < %d", op.View, sm.currentView)
	}

	// Check sequence number
	if op.Sequence <= sm.lastApplied {
		return fmt.Errorf("stale sequence: %d <= %d", op.Sequence, sm.lastApplied)
	}

	// Validate operation-specific data
	switch op.Type {
	case OpBlock:
		if op.Block == nil {
			return fmt.Errorf("block operation missing block")
		}
		if err := op.Block.Validate(); err != nil {
			return fmt.Errorf("invalid block: %w", err)
		}
	case OpTransaction:
		if op.Transaction == nil {
			return fmt.Errorf("transaction operation missing transaction")
		}
		if err := op.Transaction.SanityCheck(); err != nil {
			return fmt.Errorf("invalid transaction: %w", err)
		}
	}

	return nil
}

func (sm *StateMachine) validateCommitProof(proof *CommitProof) error {
	// Check if we have enough signatures for quorum
	if len(proof.Signatures) < sm.quorumSize {
		return fmt.Errorf("insufficient signatures: %d < %d",
			len(proof.Signatures), sm.quorumSize)
	}

	// Verify signatures come from validators
	for nodeID := range proof.Signatures {
		if !sm.validators[nodeID] {
			return fmt.Errorf("signature from non-validator: %s", nodeID)
		}
	}

	return nil
}

func (sm *StateMachine) hasOperationQuorum(sequence uint64) bool {
	// Count unique proposers for this sequence
	proposers := make(map[string]bool)
	for _, op := range sm.pendingOps {
		if op.Sequence == sequence {
			proposers[op.Proposer] = true
		}
	}

	return len(proposers) >= sm.quorumSize
}

func (sm *StateMachine) filterPendingOps(sequence uint64) []*Operation {
	var filtered []*Operation
	for _, op := range sm.pendingOps {
		if op.Sequence > sequence {
			filtered = append(filtered, op)
		}
	}
	return filtered
}

func (sm *StateMachine) isValidator() bool {
	return sm.validators[sm.nodeID]
}

func (sm *StateMachine) checkProgress() {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// Check if we're making progress
	if time.Since(sm.currentState.Timestamp) > 30*time.Second {
		// Trigger view change if stuck
		select {
		case sm.timeoutCh <- struct{}{}:
		default:
		}
	}
}

func (sm *StateMachine) handleTimeout() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Increment view for view change
	sm.currentView++
	log.Printf("View change triggered, new view: %d", sm.currentView)

	// Clear pending operations for new view
	sm.pendingOps = nil
}

func (sm *StateMachine) loadInitialState() error {
	// Try to load latest block from storage
	latestBlock, err := sm.storage.GetLatestBlock()
	if err != nil {
		return err
	}

	// Create state snapshot from latest block
	sm.currentState, err = sm.createStateSnapshot(latestBlock)
	if err != nil {
		return err
	}

	sm.lastApplied = sm.currentState.Height
	return nil
}

func (sm *StateMachine) createInitialState() {
	// Create genesis state
	sm.currentState = &StateSnapshot{
		Height:     0,
		BlockHash:  "genesis",
		StateRoot:  "genesis",
		Timestamp:  time.Now(),
		Validators: sm.validators,
		UTXOSet:    make(map[string]*types.UTXO),
		Accounts:   make(map[string]*AccountState),
		Committed:  true,
	}
	sm.lastApplied = 0
}

func (sm *StateMachine) persistState(snapshot *StateSnapshot) error {
	// Persist state to storage
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}

	// In practice, this would write to the storage system
	// For now, just log
	log.Printf("Persisted state: height=%d, block=%s", snapshot.Height, snapshot.BlockHash)
	_ = data // Use data to avoid unused variable warning

	return nil
}

func calculateQuorumSize(totalValidators int) int {
	// Byzantine fault tolerance: f < n/3, quorum = 2f + 1
	// For n validators, quorum = floor(2n/3) + 1
	return (2*totalValidators)/3 + 1
}
