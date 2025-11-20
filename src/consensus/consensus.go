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

// go/src/consensus/consensus.go
package consensus

import (
	"context"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/sphinx-core/go/src/common"
	logger "github.com/sphinx-core/go/src/log"
)

// Workflow: Prepare Phase → Commit Phase → Block Commitment → View Change → Repeat

// NewConsensus creates a new consensus instance with context
func NewConsensus(
	nodeID string,
	nodeManager NodeManager,
	blockchain BlockChain,
	signingService *SigningService,
	onCommit func(Block) error,
) *Consensus {

	ctx, cancel := context.WithCancel(context.Background())

	return &Consensus{
		nodeID:           nodeID,
		nodeManager:      nodeManager,
		blockChain:       blockchain,
		signingService:   signingService,
		currentView:      0,                                 // Start at view 0
		currentHeight:    0,                                 // Start at height 0
		phase:            PhaseIdle,                         // Initial phase is idle
		quorumFraction:   0.67,                              // 2/3 quorum required for Byzantine fault tolerance
		timeout:          60 * time.Second,                  // View change timeout
		receivedVotes:    make(map[string]map[string]*Vote), // Track commit votes by block hash
		prepareVotes:     make(map[string]map[string]*Vote), // Track prepare votes by block hash
		sentVotes:        make(map[string]bool),             // Track which votes this node has sent
		sentPrepareVotes: make(map[string]bool),             // Track which prepare votes this node has sent
		proposalCh:       make(chan *Proposal, 100),         // Channel for incoming proposals
		voteCh:           make(chan *Vote, 1000),            // Channel for incoming commit votes
		timeoutCh:        make(chan *TimeoutMsg, 100),       // Channel for timeout messages
		prepareCh:        make(chan *Vote, 1000),            // Channel for incoming prepare votes
		onCommit:         onCommit,                          // Callback for committed blocks
		ctx:              ctx,                               // Context for cancellation
		cancel:           cancel,                            // Cancel function for shutdown
		lastViewChange:   common.GetTimeService().Now(),     // Initialize last view change time using centralized time
		viewChangeMutex:  sync.Mutex{},                      // Initialize view change mutex
		lastBlockTime:    common.GetTimeService().Now(),     // Initialize last block time using centralized time
	}
}

// Start begins the consensus process by launching all message handlers
// Returns error if consensus cannot be started
func (c *Consensus) Start() error {
	logger.Info("Consensus started for node %s", c.nodeID)

	// Start message handlers in separate goroutines
	go c.handleProposals()    // Handle incoming block proposals
	go c.handleVotes()        // Handle incoming commit votes
	go c.handlePrepareVotes() // Handle incoming prepare votes
	go c.handleTimeouts()     // Handle timeout messages
	go c.consensusLoop()      // Main consensus loop

	return nil
}

// GetNodeID returns the node ID of this consensus instance
func (c *Consensus) GetNodeID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.nodeID
}

// Add this method to consensus.go
func (c *Consensus) SetTimeout(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.timeout = d
}

// Stop halts the consensus process and cleans up resources
// Returns error if consensus cannot be stopped properly
func (c *Consensus) Stop() error {
	logger.Info("Consensus stopped for node %s", c.nodeID)
	c.cancel() // Cancel context to signal all goroutines to stop
	return nil
}

// ProposeBlock proposes a new block for consensus (called by leader)
// block: The block to be proposed for consensus
// Returns error if node is not leader or proposal fails
// ProposeBlock with proper signing
func (c *Consensus) ProposeBlock(block Block) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isLeader {
		return fmt.Errorf("node %s is not the leader", c.nodeID)
	}

	// Create proposal
	proposal := &Proposal{
		Block:      block,
		View:       c.currentView,
		ProposerID: c.nodeID,
		Signature:  []byte{}, // Initialize empty, will be signed
	}

	// Sign the proposal
	if c.signingService != nil {
		if err := c.signingService.SignProposal(proposal); err != nil {
			return fmt.Errorf("failed to sign proposal: %v", err)
		}
	} else {
		logger.Warn("WARNING: No signing service available, sending unsigned proposal")
	}

	logger.Info("Node %s proposing block %s at view %d", c.nodeID, block.GetHash(), c.currentView)
	return c.broadcastProposal(proposal)
}

// HandleProposal processes incoming block proposals from other nodes
// proposal: The received block proposal
// Returns error if consensus is stopped or channel is full
func (c *Consensus) HandleProposal(proposal *Proposal) error {
	select {
	case c.proposalCh <- proposal:
		return nil
	case <-c.ctx.Done():
		return fmt.Errorf("consensus stopped")
	}
}

// HandleVote processes incoming commit votes from other validators
// vote: The received commit vote
// Returns error if consensus is stopped or channel is full
func (c *Consensus) HandleVote(vote *Vote) error {
	select {
	case c.voteCh <- vote:
		return nil
	case <-c.ctx.Done():
		return fmt.Errorf("consensus stopped")
	}
}

// HandlePrepareVote processes incoming prepare votes from other validators
// vote: The received prepare vote
// Returns error if consensus is stopped or channel is full
func (c *Consensus) HandlePrepareVote(vote *Vote) error {
	select {
	case c.prepareCh <- vote:
		return nil
	case <-c.ctx.Done():
		return fmt.Errorf("consensus stopped")
	}
}

// HandleTimeout processes incoming timeout messages for view changes
// timeout: The received timeout message
// Returns error if consensus is stopped or channel is full
func (c *Consensus) HandleTimeout(timeout *TimeoutMsg) error {
	select {
	case c.timeoutCh <- timeout:
		return nil
	case <-c.ctx.Done():
		return fmt.Errorf("consensus stopped")
	}
}

// GetCurrentView returns the current view number
// View represents the current consensus round
func (c *Consensus) GetCurrentView() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentView
}

// IsLeader returns whether this node is the current leader
// Leader is responsible for proposing blocks in the current view
func (c *Consensus) IsLeader() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.isLeader
}

// GetPhase returns the current consensus phase
// Phase indicates the progress in the PBFT consensus protocol
func (c *Consensus) GetPhase() ConsensusPhase {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.phase
}

// GetCurrentHeight returns the current block height
// Height represents the number of blocks committed in the chain
func (c *Consensus) GetCurrentHeight() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentHeight
}

// Private methods

// consensusLoop is the main consensus loop that handles view change timeouts
// Monitors for view timeouts and initiates view changes when necessary
func (c *Consensus) consensusLoop() {
	viewTimer := time.NewTimer(c.timeout)
	defer viewTimer.Stop()

	for {
		select {
		case <-viewTimer.C:
			// View timeout occurred, initiate view change
			c.startViewChange()
			viewTimer.Reset(c.timeout)
		case <-c.ctx.Done():
			// Consensus stopped, exit loop
			logger.Info("Consensus loop stopped for node %s", c.nodeID)
			return
		}
	}
}

// handleProposals processes incoming block proposals from the proposal channel
// Continuously reads proposals and processes them until consensus stops
func (c *Consensus) handleProposals() {
	for {
		select {
		case proposal, ok := <-c.proposalCh:
			if !ok {
				return // Channel closed
			}
			c.processProposal(proposal)
		case <-c.ctx.Done():
			logger.Info("Proposal handler stopped for node %s", c.nodeID)
			return
		}
	}
}

// handleVotes processes incoming commit votes from the vote channel
// Continuously reads votes and processes them until consensus stops
func (c *Consensus) handleVotes() {
	for {
		select {
		case vote, ok := <-c.voteCh:
			if !ok {
				return // Channel closed
			}
			c.processVote(vote)
		case <-c.ctx.Done():
			logger.Info("Vote handler stopped for node %s", c.nodeID)
			return
		}
	}
}

// handlePrepareVotes processes incoming prepare votes from the prepare channel
// Continuously reads prepare votes and processes them until consensus stops
func (c *Consensus) handlePrepareVotes() {
	for {
		select {
		case vote, ok := <-c.prepareCh:
			if !ok {
				return // Channel closed
			}
			c.processPrepareVote(vote)
		case <-c.ctx.Done():
			logger.Info("Prepare vote handler stopped for node %s", c.nodeID)
			return
		}
	}
}

// handleTimeouts processes incoming timeout messages from the timeout channel
// Continuously reads timeout messages and processes them until consensus stops
func (c *Consensus) handleTimeouts() {
	for {
		select {
		case timeout, ok := <-c.timeoutCh:
			if !ok {
				return // Channel closed
			}
			c.processTimeout(timeout)
		case <-c.ctx.Done():
			logger.Info("Timeout handler stopped for node %s", c.nodeID)
			return
		}
	}
}

// updateLeaderStatus updates the leader status based on current view and validators
func (c *Consensus) updateLeaderStatus() {
	c.mu.Lock()
	defer c.mu.Unlock()

	validators := c.getValidators()
	if len(validators) == 0 {
		c.isLeader = false
		return
	}

	// Sort validators for deterministic leader selection
	sort.Strings(validators)

	// Round-robin leader selection based on view number
	leaderIndex := int(c.currentView) % len(validators)
	expectedLeader := validators[leaderIndex]

	c.isLeader = (expectedLeader == c.nodeID)

	if c.isLeader {
		logger.Info("✅ Node %s is leader for view %d (index %d/%d)",
			c.nodeID, c.currentView, leaderIndex, len(validators))
	} else {
		logger.Info("Node %s is NOT leader for view %d (leader is %s)",
			c.nodeID, c.currentView, expectedLeader)
	}
}

// processProposal handles a received block proposal
func (c *Consensus) processProposal(proposal *Proposal) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// FIX: Check if we already have a prepared block for this height
	if c.preparedBlock != nil && c.preparedBlock.GetHeight() == proposal.Block.GetHeight() {
		logger.Warn("❌ Already have prepared block for height %d, ignoring duplicate proposal",
			proposal.Block.GetHeight())
		return
	}

	logger.Info("🔍 DEBUG: Starting processProposal for view %d from %s", proposal.View, proposal.ProposerID)

	// DEBUG: Log the previous hash to see what's happening
	prevHash := proposal.Block.GetPrevHash()
	logger.Info("🔍 DEBUG: Previous hash in proposal: %s", prevHash)

	// Verify signature if signing service is available
	if c.signingService != nil && len(proposal.Signature) > 0 {
		valid, err := c.signingService.VerifyProposal(proposal)
		if err != nil {
			logger.Warn("❌ Error verifying proposal signature from %s: %v", proposal.ProposerID, err)
			return
		}
		if !valid {
			logger.Warn("❌ Invalid proposal signature from %s", proposal.ProposerID)
			return
		}
		logger.Info("✅ Valid signature for proposal from %s", proposal.ProposerID)
	} else {
		logger.Warn("⚠️ No signing service or empty signature, skipping verification")
	}

	// Capture signature for storage
	signatureHex := hex.EncodeToString(proposal.Signature)

	// Store signature in chain state
	consensusSig := &ConsensusSignature{
		BlockHash:    proposal.Block.GetHash(),
		BlockHeight:  proposal.Block.GetHeight(),
		SignerNodeID: proposal.ProposerID,
		Signature:    signatureHex,
		MessageType:  "proposal",
		View:         proposal.View,
		Timestamp:    common.GetTimeService().GetCurrentTimeInfo().ISOLocal,
		Valid:        true,
	}

	// Add to signature tracking
	c.addConsensusSignature(consensusSig)

	// Check if proposal is for current or future view
	if proposal.View < c.currentView {
		logger.Warn("❌ Stale proposal for view %d, current view %d", proposal.View, c.currentView)
		return
	}

	// Update to new view if proposal is for future view
	if proposal.View > c.currentView {
		logger.Info("🔄 Advancing view from %d to %d", c.currentView, proposal.View)
		c.currentView = proposal.View
		c.resetConsensusState()
		c.updateLeaderStatus()
	}

	// Validate the proposed block height
	currentHeight := c.blockChain.GetLatestBlock().GetHeight()
	if proposal.Block.GetHeight() != currentHeight+1 {
		logger.Warn("❌ Invalid block height: expected %d, got %d",
			currentHeight+1, proposal.Block.GetHeight())
		return
	}

	// FIX: The issue might be in block validation - add detailed logging
	logger.Info("🔍 DEBUG: Starting blockchain validation for block %s", proposal.Block.GetHash())
	if err := c.blockChain.ValidateBlock(proposal.Block); err != nil {
		logger.Warn("❌ Invalid block in proposal: %v", err)
		return
	}
	logger.Info("✅ Blockchain validation passed for block %s", proposal.Block.GetHash())

	// Verify the proposer is the legitimate leader for this view
	if !c.isValidLeader(proposal.ProposerID, proposal.View) {
		logger.Warn("❌ Invalid leader %s for view %d", proposal.ProposerID, proposal.View)
		return
	}

	logger.Info("✅ Node %s accepting proposal for block %s at view %d (height %d)",
		c.nodeID, proposal.Block.GetHash(), proposal.View, proposal.Block.GetHeight())

	// CRITICAL FIX: Store the prepared block and move to pre-prepared phase
	c.preparedBlock = proposal.Block
	c.preparedView = proposal.View
	c.phase = PhasePrePrepared

	logger.Info("💾 Stored prepared block: hash=%s, view=%d, phase=%v",
		proposal.Block.GetHash(), proposal.View, c.phase)

	// Send prepare vote for this block
	c.sendPrepareVote(proposal.Block.GetHash(), proposal.View)
}

// processPrepareVote handles a received prepare vote
// Tracks prepare votes and progresses to prepared phase when quorum is reached
// processPrepareVote handles a received prepare vote
// Enhanced processPrepareVote method
func (c *Consensus) processPrepareVote(vote *Vote) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Verify signature if signing service is available
	if c.signingService != nil && len(vote.Signature) > 0 {
		valid, err := c.signingService.VerifyVote(vote)
		if err != nil {
			logger.Warn("Error verifying prepare vote signature from %s: %v", vote.VoterID, err)
			return
		}
		if !valid {
			logger.Warn("Invalid prepare vote signature from %s", vote.VoterID)
			return
		}
	}

	// FIX: If we receive prepare votes for a block we don't have, try to find it
	if c.preparedBlock == nil || c.preparedBlock.GetHash() != vote.BlockHash {
		// Look for the block in our recent proposals or ask peers
		logger.Warn("❌ No prepared block found for hash %s, attempting recovery", vote.BlockHash)

		// FIX: Correct assignment - GetBlockByHash returns only one value
		block := c.blockChain.GetBlockByHash(vote.BlockHash)
		if block != nil {
			c.preparedBlock = block
			c.preparedView = vote.View
			logger.Info("✅ Recovered prepared block from storage: %s", vote.BlockHash)
		} else {
			logger.Warn("❌ Cannot recover block %s, ignoring prepare votes", vote.BlockHash)
			return
		}
	}

	// Initialize vote tracking for this block hash if needed
	if c.prepareVotes[vote.BlockHash] == nil {
		c.prepareVotes[vote.BlockHash] = make(map[string]*Vote)
	}

	// Store the prepare vote
	c.prepareVotes[vote.BlockHash][vote.VoterID] = vote

	totalVotes := len(c.prepareVotes[vote.BlockHash])
	quorumSize := c.calculateQuorumSize(c.getTotalNodes())

	logger.Info("📊 Prepare vote received: node=%s, from=%s, block=%s, votes=%d/%d, phase=%v, prepared=%v",
		c.nodeID, vote.VoterID, vote.BlockHash, totalVotes, quorumSize, c.phase, c.preparedBlock != nil)

	// Check if we have enough prepare votes to progress
	if c.hasPrepareQuorum(vote.BlockHash) {
		logger.Info("🎉 PREPARE QUORUM ACHIEVED for block %s at view %d", vote.BlockHash, vote.View)

		// CRITICAL FIX: Ensure we have the prepared block
		if c.preparedBlock == nil || c.preparedBlock.GetHash() != vote.BlockHash {
			logger.Warn("❌ No prepared block found for hash %s (have: %v)",
				vote.BlockHash, c.preparedBlock != nil)
			if c.preparedBlock != nil {
				logger.Warn("   Current prepared block hash: %s", c.preparedBlock.GetHash())
			}
			return
		}
		// Capture prepare vote signature
		signatureHex := hex.EncodeToString(vote.Signature)
		consensusSig := &ConsensusSignature{
			BlockHash:    vote.BlockHash,
			BlockHeight:  c.currentHeight,
			SignerNodeID: vote.VoterID,
			Signature:    signatureHex,
			MessageType:  "prepare",
			View:         vote.View,
			Timestamp:    common.GetTimeService().GetCurrentTimeInfo().ISOLocal, // Use centralized time
			Valid:        true,
		}
		c.addConsensusSignature(consensusSig)

		// Move to prepared phase only if we're in pre-prepared phase
		if c.phase == PhasePrePrepared {
			c.phase = PhasePrepared
			c.lockedBlock = c.preparedBlock
			logger.Info("🔒 Moving to PREPARED phase and locking block %s", vote.BlockHash)

			// Send commit vote
			c.voteForBlock(vote.BlockHash, vote.View)
		} else {
			logger.Info("⚠️ Already in phase %v, skipping phase transition", c.phase)
		}
	}
}

func (c *Consensus) addConsensusSignature(sig *ConsensusSignature) {
	c.signatureMutex.Lock()
	defer c.signatureMutex.Unlock()
	c.consensusSignatures = append(c.consensusSignatures, sig)
}

func (c *Consensus) GetConsensusSignatures() []*ConsensusSignature {
	c.signatureMutex.RLock()
	defer c.signatureMutex.RUnlock()

	// Return a copy to avoid concurrent modification
	signatures := make([]*ConsensusSignature, len(c.consensusSignatures))
	copy(signatures, c.consensusSignatures)
	return signatures
}

// processVote handles a received commit vote
// Tracks commit votes and commits block when quorum is reached
// Enhanced processVote method to ensure commit happens
// Enhanced processVote method
func (c *Consensus) processVote(vote *Vote) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Verify signature if signing service is available
	if c.signingService != nil && len(vote.Signature) > 0 {
		valid, err := c.signingService.VerifyVote(vote)
		if err != nil {
			logger.Warn("Error verifying commit vote signature from %s: %v", vote.VoterID, err)
			return
		}
		if !valid {
			logger.Warn("Invalid commit vote signature from %s", vote.VoterID)
			return
		}
		logger.Debug("✅ Valid commit vote signature from %s", vote.VoterID)
	}

	// Initialize vote tracking for this block hash if needed
	if c.receivedVotes[vote.BlockHash] == nil {
		c.receivedVotes[vote.BlockHash] = make(map[string]*Vote)
	}

	// Store the commit vote
	c.receivedVotes[vote.BlockHash][vote.VoterID] = vote

	totalVotes := len(c.receivedVotes[vote.BlockHash])
	quorumSize := c.calculateQuorumSize(c.getTotalNodes())

	logger.Info("📊 Commit vote received: node=%s, from=%s, block=%s, votes=%d/%d, phase=%v",
		c.nodeID, vote.VoterID, vote.BlockHash, totalVotes, quorumSize, c.phase)

	// Check if we have enough commit votes to commit the block
	if c.hasQuorum(vote.BlockHash) {
		logger.Info("🎉 COMMIT QUORUM ACHIEVED for block %s at view %d", vote.BlockHash, vote.View)

		// Find the block to commit
		var blockToCommit Block
		if c.lockedBlock != nil && c.lockedBlock.GetHash() == vote.BlockHash {
			blockToCommit = c.lockedBlock
		} else if c.preparedBlock != nil && c.preparedBlock.GetHash() == vote.BlockHash {
			blockToCommit = c.preparedBlock
		} else {
			logger.Warn("❌ No block found to commit for hash %s", vote.BlockHash)
			return
		}

		// Ensure we're in the correct phase
		if c.phase != PhaseCommitted {
			c.phase = PhaseCommitted
			logger.Info("🚀 Moving to COMMITTED phase for block %s", vote.BlockHash)
		}

		// Capture vote signature
		signatureHex := hex.EncodeToString(vote.Signature)
		consensusSig := &ConsensusSignature{
			BlockHash:    vote.BlockHash,
			BlockHeight:  c.currentHeight, // You might need to track this differently
			SignerNodeID: vote.VoterID,
			Signature:    signatureHex,
			MessageType:  "commit",
			View:         vote.View,
			Timestamp:    common.GetTimeService().GetCurrentTimeInfo().ISOLocal, // Use centralized time
			Valid:        true,
		}
		c.addConsensusSignature(consensusSig)

		// Commit the block
		c.commitBlock(blockToCommit)
	}
}

// processTimeout handles a received timeout message with proper mutex handling
func (c *Consensus) processTimeout(timeout *TimeoutMsg) {
	c.mu.Lock()
	defer c.mu.Unlock() // Use defer to ensure unlock happens exactly once

	logger.Debug("Processing timeout from %s for view %d (current view: %d)",
		timeout.VoterID, timeout.View, c.currentView)

	// Verify signature if signing service is available
	if c.signingService != nil && len(timeout.Signature) > 0 {
		valid, err := c.signingService.VerifyTimeout(timeout)
		if err != nil {
			logger.Warn("Error verifying timeout signature from %s: %v", timeout.VoterID, err)
			return // Mutex will be unlocked by defer
		}
		if !valid {
			logger.Warn("Invalid timeout signature from %s", timeout.VoterID)
			return // Mutex will be unlocked by defer
		}
		logger.Debug("✅ Valid timeout signature from %s", timeout.VoterID)
	} else if c.signingService == nil {
		logger.Warn("WARNING: No signing service, accepting unsigned timeout from %s", timeout.VoterID)
	} else {
		logger.Warn("WARNING: Empty signature from %s, accepting timeout", timeout.VoterID)
	}

	// Only process timeouts for future views
	if timeout.View > c.currentView {
		logger.Info("View change requested to view %d by %s", timeout.View, timeout.VoterID)
		c.currentView = timeout.View
		c.lastViewChange = common.GetTimeService().Now() // Use centralized time
		c.resetConsensusState()

		// Update leader status immediately
		validators := c.getValidators()
		c.updateLeaderStatusWithValidators(validators)

		logger.Info("View change completed: node=%s, new_view=%d, leader=%v",
			c.nodeID, c.currentView, c.isLeader)
	} else if timeout.View == c.currentView {
		logger.Debug("Ignoring timeout for current view %d", timeout.View)
	} else {
		logger.Debug("Ignoring stale timeout for view %d (current: %d)", timeout.View, c.currentView)
	}
	// Mutex automatically unlocked by defer
}

// sendPrepareVote sends a prepare vote for a specific block
// blockHash: The hash of the block being voted on
// view: The consensus view number
// sendPrepareVote with proper signing
func (c *Consensus) sendPrepareVote(blockHash string, view uint64) {
	if c.sentPrepareVotes[blockHash] {
		return
	}

	prepareVote := &Vote{
		BlockHash: blockHash,
		View:      view,
		VoterID:   c.nodeID,
		Signature: []byte{}, // Initialize empty
	}

	// Sign the prepare vote
	if c.signingService != nil {
		if err := c.signingService.SignVote(prepareVote); err != nil {
			logger.Warn("Failed to sign prepare vote: %v", err)
			return
		}
	} else {
		logger.Warn("WARNING: No signing service available, sending unsigned prepare vote")
	}

	// Mark vote as sent and broadcast it
	c.sentPrepareVotes[blockHash] = true
	c.broadcastPrepareVote(prepareVote)

	logger.Info("Node %s sent prepare vote for block %s at view %d", c.nodeID, blockHash, view)
}

// voteForBlock sends a commit vote for a specific block
// blockHash: The hash of the block being voted on
// view: The consensus view number
// Enhanced voteForBlock method with logging
func (c *Consensus) voteForBlock(blockHash string, view uint64) {
	if c.sentVotes[blockHash] {
		logger.Debug("Already sent commit vote for block %s", blockHash)
		return
	}

	// Find the block to vote for (for logging)
	var blockToVote Block
	if c.lockedBlock != nil && c.lockedBlock.GetHash() == blockHash {
		blockToVote = c.lockedBlock
	} else if c.preparedBlock != nil && c.preparedBlock.GetHash() == blockHash {
		blockToVote = c.preparedBlock
	} else {
		logger.Warn("❌ No block found to vote for hash %s", blockHash)
		return
	}

	vote := &Vote{
		BlockHash: blockHash,
		View:      view,
		VoterID:   c.nodeID,
		Signature: []byte{},
	}

	// Sign the commit vote
	if c.signingService != nil {
		if err := c.signingService.SignVote(vote); err != nil {
			logger.Warn("Failed to sign commit vote: %v", err)
			return
		}
	}

	// Mark vote as sent and broadcast it
	c.sentVotes[blockHash] = true
	c.broadcastVote(vote)

	logger.Info("🗳️ Node %s sent COMMIT vote for block %s (height %d) at view %d",
		c.nodeID, blockHash, blockToVote.GetHeight(), view)
}

// hasPrepareQuorum checks if enough prepare votes have been received for a block
// blockHash: The hash of the block to check
// Returns true if prepare quorum is achieved
func (c *Consensus) hasPrepareQuorum(blockHash string) bool {
	votes := c.prepareVotes[blockHash]
	if votes == nil {
		return false
	}
	return len(votes) >= c.calculateQuorumSize(c.getTotalNodes())
}

// hasQuorum checks if enough commit votes have been received for a block
// blockHash: The hash of the block to check
// Returns true if commit quorum is achieved
func (c *Consensus) hasQuorum(blockHash string) bool {
	votes := c.receivedVotes[blockHash]
	if votes == nil {
		return false
	}
	return len(votes) >= c.calculateQuorumSize(c.getTotalNodes())
}

// calculateQuorumSize calculates the minimum number of votes needed for quorum
// totalNodes: Total number of active validator nodes
// Returns the quorum size (minimum votes required)
func (c *Consensus) calculateQuorumSize(totalNodes int) int {
	quorumSize := int(float64(totalNodes) * c.quorumFraction)
	if quorumSize < 1 {
		return 1 // Ensure at least 1 vote is required
	}
	return quorumSize
}

// getTotalNodes counts the total number of active validator nodes
// Includes both peers and self if this node is a validator
// Returns total count of active validators
func (c *Consensus) getTotalNodes() int {
	peers := c.nodeManager.GetPeers()
	validatorCount := 0

	// Count active validator peers
	for _, peer := range peers {
		node := peer.GetNode()
		if node.GetRole() == RoleValidator && node.GetStatus() == NodeStatusActive {
			validatorCount++
		}
	}

	// Include self if this node is a validator
	if c.isValidator() {
		validatorCount++
	}

	return validatorCount
}

// commitBlock commits a block to the blockchain
func (c *Consensus) commitBlock(block Block) {
	logger.Info("🚀 Node %s attempting to commit block %s at height %d",
		c.nodeID, block.GetHash(), block.GetHeight())

	// Verify this is the next expected block
	currentHeight := c.blockChain.GetLatestBlock().GetHeight()
	if block.GetHeight() != currentHeight+1 {
		logger.Warn("❌ Block height mismatch: expected %d, got %d", currentHeight+1, block.GetHeight())
		return
	}

	// Commit block to blockchain storage
	if err := c.blockChain.CommitBlock(block); err != nil {
		logger.Error("❌ Error committing block: %v", err)
		return
	}

	// Execute commit callback if provided
	if c.onCommit != nil {
		if err := c.onCommit(block); err != nil {
			logger.Warn("⚠️ Error in commit callback: %v", err)
			// Don't return here - we still want to update consensus state
		}
	}

	// Update consensus state and set last block time
	c.mu.Lock()
	c.currentHeight = block.GetHeight()
	c.lastBlockTime = common.GetTimeService().Now() // Update the last block time using centralized time
	c.resetConsensusState()
	c.mu.Unlock()

	logger.Info("🎉 Node %s successfully committed block %s at height %d",
		c.nodeID, block.GetHash(), c.currentHeight)
}

// startViewChange initiates a view change to the next view with aggressive prevention
// to avoid rapid view changes and maintain consensus stability
func (c *Consensus) startViewChange() {
	// Try to acquire view change lock with timeout
	if !c.tryViewChangeLock() {
		logger.Debug("View change already in progress for node %s", c.nodeID)
		return
	}
	defer c.viewChangeMutex.Unlock()

	c.mu.Lock()

	// Prevent view changes if we're actively processing consensus
	if c.phase != PhaseIdle && c.phase != PhaseCommitted {
		logger.Debug("Skipping view change - active consensus in phase %v", c.phase)
		c.mu.Unlock()
		return
	}

	// Extended cooldown period: prevent view changes for at least 15 seconds
	if common.GetTimeService().Now().Sub(c.lastViewChange) < 15*time.Second {
		logger.Debug("Skipping view change for node %s (cooldown: %v since last view change)",
			c.nodeID, common.GetTimeService().Now().Sub(c.lastViewChange))
		c.mu.Unlock()
		return
	}

	// Only proceed with view change if we're significantly behind in block production
	if c.currentHeight > 0 && common.GetTimeService().Now().Sub(c.lastBlockTime) < 30*time.Second {
		logger.Debug("Skipping view change for node %s (recent block activity: %v since last block)",
			c.nodeID, common.GetTimeService().Now().Sub(c.lastBlockTime))
		c.mu.Unlock()
		return
	}

	// Check if we have validators available
	validators := c.getValidators()
	if len(validators) == 0 {
		logger.Warn("Skipping view change - no validators available")
		c.mu.Unlock()
		return
	}

	newView := c.currentView + 1
	logger.Info("🔄 Node %s initiating view change to view %d (current height: %d, phase: %v)",
		c.nodeID, newView, c.currentHeight, c.phase)

	// Update consensus state
	c.currentView = newView
	c.lastViewChange = common.GetTimeService().Now() // Use centralized time
	c.resetConsensusState()

	// Update leader status
	c.updateLeaderStatusWithValidators(validators)

	c.mu.Unlock() // Unlock before network operations

	// Create and sign timeout message
	timeoutMsg := &TimeoutMsg{
		View:      newView,
		VoterID:   c.nodeID,
		Signature: []byte{},
		Timestamp: common.GetCurrentTimestamp(), // Use centralized time service
	}

	// Sign the timeout message if signing service is available
	if c.signingService != nil {
		if err := c.signingService.SignTimeout(timeoutMsg); err != nil {
			logger.Warn("Failed to sign timeout message for view %d: %v", newView, err)
			return // Don't re-lock, we're already unlocked
		}
	} else {
		logger.Warn("WARNING: No signing service available, sending unsigned timeout message")
	}

	// Broadcast timeout message to all peers
	if err := c.broadcastTimeout(timeoutMsg); err != nil {
		logger.Warn("Failed to broadcast timeout message for view %d: %v", newView, err)
		return // Don't re-lock
	}

	logger.Info("✅ View change initiated: node=%s, view=%d, new_leader=%v",
		c.nodeID, newView, c.isLeader)
}

// Helper method to safely acquire view change lock
// tryViewChangeLock attempts to acquire the view change lock with a timeout
// Returns true if lock was acquired, false otherwise
func (c *Consensus) tryViewChangeLock() bool {
	// Try to acquire the view change mutex without blocking for too long
	acquired := make(chan bool, 1)

	go func() {
		c.viewChangeMutex.Lock()
		acquired <- true
	}()

	select {
	case <-acquired:
		return true
	case <-time.After(100 * time.Millisecond):
		return false // Couldn't acquire lock in time
	case <-c.ctx.Done():
		return false // Consensus stopped
	}
}

// updateLeaderStatusWithValidators updates the leader status based on current view and validators
func (c *Consensus) updateLeaderStatusWithValidators(validators []string) {
	if len(validators) == 0 {
		c.isLeader = false
		logger.Warn("No validators available for leader election")
		return
	}

	// Sort validators for deterministic leader selection
	sort.Strings(validators)

	// Round-robin leader selection based on view number
	leaderIndex := int(c.currentView) % len(validators)
	expectedLeader := validators[leaderIndex]

	c.isLeader = (expectedLeader == c.nodeID)

	if c.isLeader {
		logger.Info("✅ Node %s elected as leader for view %d (index %d/%d, validators: %v)",
			c.nodeID, c.currentView, leaderIndex, len(validators), validators)
	} else {
		logger.Debug("Node %s is NOT leader for view %d (leader is %s, index %d/%d)",
			c.nodeID, c.currentView, expectedLeader, leaderIndex, len(validators))
	}
}

// resetConsensusState resets the consensus state to initial values
// Called when starting new view or after block commitment
func (c *Consensus) resetConsensusState() {
	c.phase = PhaseIdle
	c.lockedBlock = nil
	c.preparedBlock = nil
	c.preparedView = 0
	c.receivedVotes = make(map[string]map[string]*Vote)
	c.prepareVotes = make(map[string]map[string]*Vote)
	c.sentVotes = make(map[string]bool)
	c.sentPrepareVotes = make(map[string]bool)

	logger.Debug("Consensus state reset for node %s (view: %d)", c.nodeID, c.currentView)
}

// isValidLeader checks if a node is the legitimate leader for a given view
// nodeID: The node ID to check
// view: The consensus view number
// Returns true if the node is the legitimate leader for this view
// isValidLeader checks if a node is the legitimate leader for a given view
func (c *Consensus) isValidLeader(nodeID string, view uint64) bool {
	validators := c.getValidators()
	if len(validators) == 0 {
		return false
	}

	// Sort validators for deterministic leader selection
	sort.Strings(validators)

	// Round-robin leader selection based on view number
	leaderIndex := int(view) % len(validators)
	expectedLeader := validators[leaderIndex]

	isValid := expectedLeader == nodeID

	// Enhanced logging for debugging
	if isValid {
		logger.Info("✅ Valid leader: %s for view %d (index %d/%d)",
			nodeID, view, leaderIndex, len(validators))
	} else {
		logger.Info("❌ Invalid leader: expected %s for view %d (index %d/%d), got %s",
			expectedLeader, view, leaderIndex, len(validators), nodeID)
		logger.Info("   Validators: %v", validators)
	}

	return isValid
}

// getValidators gets the list of active validator node IDs without duplicates
// Enhanced getValidators with better error handling and logging
// getValidators gets the list of active validator node IDs without duplicates
func (c *Consensus) getValidators() []string {
	peers := c.nodeManager.GetPeers()
	validatorSet := make(map[string]bool)
	validators := []string{}

	// Always include self if we're a validator
	if c.isValidator() {
		validatorSet[c.nodeID] = true
		validators = append(validators, c.nodeID)
	}

	// Collect validator peers
	for _, peer := range peers {
		node := peer.GetNode()
		if node != nil && node.GetRole() == RoleValidator && node.GetStatus() == NodeStatusActive {
			nodeID := node.GetID()
			if !validatorSet[nodeID] && nodeID != "" {
				validatorSet[nodeID] = true
				validators = append(validators, nodeID)
			}
		}
	}

	// Sort for deterministic ordering
	sort.Strings(validators)

	if len(validators) == 0 {
		logger.Error("CRITICAL: No validators found for consensus!")
		// Return at least self to prevent complete failure
		return []string{c.nodeID}
	}

	return validators
}

// isValidator checks if this node is a validator
// isValidator checks if this node is a validator
func (c *Consensus) isValidator() bool {
	self := c.nodeManager.GetNode(c.nodeID)
	return self != nil && self.GetRole() == RoleValidator
}

// SetLastBlockTime updates the last block time to track recent block activity
// This should be called whenever a block is committed
func (c *Consensus) SetLastBlockTime(blockTime time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastBlockTime = blockTime
	logger.Debug("Updated last block time for node %s: %v", c.nodeID, blockTime)
}

// GetConsensusState returns a string representation of the current consensus state for debugging
func (c *Consensus) GetConsensusState() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	preparedHash := ""
	if c.preparedBlock != nil {
		preparedHash = c.preparedBlock.GetHash()
	}

	lockedHash := ""
	if c.lockedBlock != nil {
		lockedHash = c.lockedBlock.GetHash()
	}

	// Use centralized time service for time calculations
	currentTime := common.GetTimeService().Now()
	lastViewChangeDuration := currentTime.Sub(c.lastViewChange)
	lastBlockTimeDuration := currentTime.Sub(c.lastBlockTime)

	return fmt.Sprintf(
		"Node=%s, View=%d, Phase=%v, Leader=%v, Height=%d, "+
			"PreparedBlock=%s, LockedBlock=%s, PreparedView=%d, "+
			"LastViewChange=%v, LastBlockTime=%v, "+
			"PrepareVotes=%d, CommitVotes=%d",
		c.nodeID, c.currentView, c.phase, c.isLeader, c.currentHeight,
		preparedHash, lockedHash, c.preparedView,
		lastViewChangeDuration, lastBlockTimeDuration,
		len(c.prepareVotes), len(c.receivedVotes),
	)
}

// Network communication methods
// broadcastProposal broadcasts a block proposal to all peers
// proposal: The proposal to broadcast
// Returns error if broadcast fails
func (c *Consensus) broadcastProposal(proposal *Proposal) error {
	logger.Info("Broadcasting proposal for block %s at view %d",
		proposal.Block.GetHash(), proposal.View)
	return c.nodeManager.BroadcastMessage("proposal", proposal)
}

// broadcastVote broadcasts a commit vote to all peers
// vote: The vote to broadcast
// Returns error if broadcast fails
func (c *Consensus) broadcastVote(vote *Vote) error {
	logger.Info("Broadcasting commit vote for block %s at view %d", vote.BlockHash, vote.View)
	return c.nodeManager.BroadcastMessage("vote", vote)
}

// broadcastPrepareVote broadcasts a prepare vote to all peers
// vote: The prepare vote to broadcast
// Returns error if broadcast fails
func (c *Consensus) broadcastPrepareVote(vote *Vote) error {
	logger.Info("Broadcasting prepare vote for block %s at view %d", vote.BlockHash, vote.View)
	return c.nodeManager.BroadcastMessage("prepare", vote)
}

// broadcastTimeout broadcasts a timeout message to all peers
// timeout: The timeout message to broadcast
// Returns error if broadcast fails
func (c *Consensus) broadcastTimeout(timeout *TimeoutMsg) error {
	logger.Info("Broadcasting timeout for view %d", timeout.View)
	return c.nodeManager.BroadcastMessage("timeout", timeout)
}

// SetLeader sets the leader status for this node
// isLeader: Boolean indicating whether this node should be leader
// Used for testing or manual leader assignment
func (c *Consensus) SetLeader(isLeader bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.isLeader = isLeader
	logger.Info("Node %s leader status set to %t", c.nodeID, isLeader)
}
