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
	"fmt"
	"log"
	"sort"
	"time"
)

// NewConsensus creates a new consensus instance with context
// nodeID: Unique identifier for this node
// nodeManager: Interface for network communication and peer management
// blockchain: Interface for block storage and validation
// onCommit: Callback function executed when a block is successfully committed
func NewConsensus(nodeID string, nodeManager NodeManager, blockchain BlockChain, onCommit func(Block) error) *Consensus {
	// Create cancellable context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	return &Consensus{
		nodeID:           nodeID,
		nodeManager:      nodeManager,
		blockChain:       blockchain,
		currentView:      0,                                 // Start at view 0
		currentHeight:    0,                                 // Start at height 0
		phase:            PhaseIdle,                         // Initial phase is idle
		quorumFraction:   0.67,                              // 2/3 quorum required for Byzantine fault tolerance
		timeout:          10 * time.Second,                  // View change timeout
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
	}
}

// Start begins the consensus process by launching all message handlers
// Returns error if consensus cannot be started
func (c *Consensus) Start() error {
	log.Printf("Consensus started for node %s", c.nodeID)

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
	log.Printf("Consensus stopped for node %s", c.nodeID)
	c.cancel() // Cancel context to signal all goroutines to stop
	return nil
}

// ProposeBlock proposes a new block for consensus (called by leader)
// block: The block to be proposed for consensus
// Returns error if node is not leader or proposal fails
func (c *Consensus) ProposeBlock(block Block) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Only leaders can propose blocks
	if !c.isLeader {
		return fmt.Errorf("node %s is not the leader", c.nodeID)
	}

	// Create and broadcast proposal
	proposal := &Proposal{
		Block:      block,
		View:       c.currentView,
		ProposerID: c.nodeID,
		Signature:  []byte{}, // Should be properly signed in production
	}

	log.Printf("Node %s proposing block %s at view %d", c.nodeID, block.GetHash(), c.currentView)
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
			log.Printf("Consensus loop stopped for node %s", c.nodeID)
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
			log.Printf("Proposal handler stopped for node %s", c.nodeID)
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
			log.Printf("Vote handler stopped for node %s", c.nodeID)
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
			log.Printf("Prepare vote handler stopped for node %s", c.nodeID)
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
			log.Printf("Timeout handler stopped for node %s", c.nodeID)
			return
		}
	}
}

// processProposal handles a received block proposal
// Validates the proposal and progresses consensus state if valid
// processProposal with better logging
func (c *Consensus) processProposal(proposal *Proposal) {
	c.mu.Lock()
	defer c.mu.Unlock()

	log.Printf("Node %s received proposal for view %d from %s (current view: %d)",
		c.nodeID, proposal.View, proposal.ProposerID, c.currentView)

	// Check if proposal is for current or future view
	if proposal.View < c.currentView {
		log.Printf("Stale proposal for view %d, current view %d", proposal.View, c.currentView)
		return
	}

	// Update to new view if proposal is for future view
	if proposal.View > c.currentView {
		log.Printf("Advancing view from %d to %d", c.currentView, proposal.View)
		c.currentView = proposal.View
		c.resetConsensusState()
	}

	// Validate the proposed block
	if err := c.blockChain.ValidateBlock(proposal.Block); err != nil {
		log.Printf("Invalid block in proposal: %v", err)
		return
	}

	// Verify the proposer is the legitimate leader for this view
	if !c.isValidLeader(proposal.ProposerID, proposal.View) {
		log.Printf("Invalid leader %s for view %d", proposal.ProposerID, proposal.View)
		return
	}

	log.Printf("Node %s accepting proposal for block %s at view %d",
		c.nodeID, proposal.Block.GetHash(), proposal.View)

	// Store the prepared block and move to pre-prepared phase
	c.preparedBlock = proposal.Block
	c.preparedView = proposal.View
	c.phase = PhasePrePrepared

	// Send prepare vote for this block
	c.sendPrepareVote(proposal.Block.GetHash(), proposal.View)
}

// processPrepareVote handles a received prepare vote
// Tracks prepare votes and progresses to prepared phase when quorum is reached
func (c *Consensus) processPrepareVote(vote *Vote) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Initialize vote tracking for this block hash if needed
	if c.prepareVotes[vote.BlockHash] == nil {
		c.prepareVotes[vote.BlockHash] = make(map[string]*Vote)
	}

	// Store the prepare vote
	c.prepareVotes[vote.BlockHash][vote.VoterID] = vote

	// Check if we have enough prepare votes to progress
	if c.hasPrepareQuorum(vote.BlockHash) &&
		c.phase == PhasePrePrepared &&
		c.preparedBlock != nil &&
		c.preparedBlock.GetHash() == vote.BlockHash {
		log.Printf("Prepare quorum achieved for block %s at view %d", vote.BlockHash, vote.View)
		c.phase = PhasePrepared
		c.lockedBlock = c.preparedBlock
		c.voteForBlock(vote.BlockHash, vote.View)
	}
}

// processVote handles a received commit vote
// Tracks commit votes and commits block when quorum is reached
func (c *Consensus) processVote(vote *Vote) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Initialize vote tracking for this block hash if needed
	if c.receivedVotes[vote.BlockHash] == nil {
		c.receivedVotes[vote.BlockHash] = make(map[string]*Vote)
	}

	// Store the commit vote
	c.receivedVotes[vote.BlockHash][vote.VoterID] = vote

	// Check if we have enough commit votes to commit the block
	if c.hasQuorum(vote.BlockHash) &&
		c.phase == PhasePrepared &&
		c.lockedBlock != nil &&
		c.lockedBlock.GetHash() == vote.BlockHash {
		log.Printf("Commit quorum achieved for block %s at view %d", vote.BlockHash, vote.View)
		c.phase = PhaseCommitted
		c.commitBlock(c.lockedBlock)
	}
}

// processTimeout handles a received timeout message
// Updates to new view if timeout is for a future view
func (c *Consensus) processTimeout(timeout *TimeoutMsg) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Only process timeouts for future views
	if timeout.View > c.currentView {
		log.Printf("View change requested to view %d", timeout.View)
		c.currentView = timeout.View
		c.resetConsensusState()
	}
}

// sendPrepareVote sends a prepare vote for a specific block
// blockHash: The hash of the block being voted on
// view: The consensus view number
func (c *Consensus) sendPrepareVote(blockHash string, view uint64) {
	// Avoid sending duplicate votes
	if c.sentPrepareVotes[blockHash] {
		return
	}

	prepareVote := &Vote{
		BlockHash: blockHash,
		View:      view,
		VoterID:   c.nodeID,
		Signature: []byte{}, // Should be properly signed in production
	}

	// Mark vote as sent and broadcast it
	c.sentPrepareVotes[blockHash] = true
	c.broadcastPrepareVote(prepareVote)

	log.Printf("Node %s sent prepare vote for block %s at view %d", c.nodeID, blockHash, view)
}

// voteForBlock sends a commit vote for a specific block
// blockHash: The hash of the block being voted on
// view: The consensus view number
func (c *Consensus) voteForBlock(blockHash string, view uint64) {
	// Avoid sending duplicate votes
	if c.sentVotes[blockHash] {
		return
	}

	vote := &Vote{
		BlockHash: blockHash,
		View:      view,
		VoterID:   c.nodeID,
		Signature: []byte{}, // Should be properly signed in production
	}

	// Mark vote as sent and broadcast it
	c.sentVotes[blockHash] = true
	c.broadcastVote(vote)

	log.Printf("Node %s sent commit vote for block %s at view %d", c.nodeID, blockHash, view)
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

// isValidator checks if this node is a validator
// Returns true if this node has validator role
func (c *Consensus) isValidator() bool {
	self := c.nodeManager.GetNode(c.nodeID)
	return self != nil && self.GetRole() == RoleValidator
}

// commitBlock commits a block to the blockchain
// block: The block to commit
// Updates consensus state and executes commit callback
func (c *Consensus) commitBlock(block Block) {
	log.Printf("Node %s committing block %s at height %d",
		c.nodeID, block.GetHash(), block.GetHeight())

	// Commit block to blockchain storage
	if err := c.blockChain.CommitBlock(block); err != nil {
		log.Printf("Error committing block: %v", err)
		return
	}

	// Execute commit callback if provided
	if c.onCommit != nil {
		if err := c.onCommit(block); err != nil {
			log.Printf("Error in commit callback: %v", err)
		}
	}

	// Update consensus state
	c.currentHeight = block.GetHeight() + 1
	c.resetConsensusState()
}

// startViewChange initiates a view change to the next view
// Called when view timeout occurs or received timeout messages
func (c *Consensus) startViewChange() {
	c.mu.Lock()
	defer c.mu.Unlock()

	newView := c.currentView + 1
	log.Printf("Node %s starting view change to view %d", c.nodeID, newView)

	timeoutMsg := &TimeoutMsg{
		View:      newView,
		VoterID:   c.nodeID,
		Signature: []byte{}, // Should be properly signed in production
	}

	c.broadcastTimeout(timeoutMsg)
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
	if !isValid {
		log.Printf("Invalid leader: expected %s for view %d, got %s",
			expectedLeader, view, nodeID)
	}

	return isValid
}

// getValidators gets the list of active validator node IDs
// Returns slice of validator node IDs including self if applicable
// getValidators gets the list of active validator node IDs
func (c *Consensus) getValidators() []string {
	peers := c.nodeManager.GetPeers()
	validators := []string{}

	// Collect active validator peers
	for _, peer := range peers {
		node := peer.GetNode()
		if node.GetRole() == RoleValidator && node.GetStatus() == NodeStatusActive {
			validators = append(validators, node.GetID())
		}
	}

	// Include self if this node is a validator
	if c.isValidator() {
		validators = append(validators, c.nodeID)
	}

	// Sort for deterministic ordering
	sort.Strings(validators)
	return validators
}

// Network communication methods

// broadcastProposal broadcasts a block proposal to all peers
// proposal: The proposal to broadcast
// Returns error if broadcast fails
func (c *Consensus) broadcastProposal(proposal *Proposal) error {
	log.Printf("Broadcasting proposal for block %s at view %d",
		proposal.Block.GetHash(), proposal.View)
	return c.nodeManager.BroadcastMessage("proposal", proposal)
}

// broadcastVote broadcasts a commit vote to all peers
// vote: The vote to broadcast
// Returns error if broadcast fails
func (c *Consensus) broadcastVote(vote *Vote) error {
	log.Printf("Broadcasting commit vote for block %s at view %d", vote.BlockHash, vote.View)
	return c.nodeManager.BroadcastMessage("vote", vote)
}

// broadcastPrepareVote broadcasts a prepare vote to all peers
// vote: The prepare vote to broadcast
// Returns error if broadcast fails
func (c *Consensus) broadcastPrepareVote(vote *Vote) error {
	log.Printf("Broadcasting prepare vote for block %s at view %d", vote.BlockHash, vote.View)
	return c.nodeManager.BroadcastMessage("prepare", vote)
}

// broadcastTimeout broadcasts a timeout message to all peers
// timeout: The timeout message to broadcast
// Returns error if broadcast fails
func (c *Consensus) broadcastTimeout(timeout *TimeoutMsg) error {
	log.Printf("Broadcasting timeout for view %d", timeout.View)
	return c.nodeManager.BroadcastMessage("timeout", timeout)
}

// SetLeader sets the leader status for this node
// isLeader: Boolean indicating whether this node should be leader
// Used for testing or manual leader assignment
func (c *Consensus) SetLeader(isLeader bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.isLeader = isLeader
	log.Printf("Node %s leader status set to %t", c.nodeID, isLeader)
}
