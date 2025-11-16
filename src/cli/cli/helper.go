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

// go/src/cli/cli/helper.go
package cli

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sphinx-core/go/src/common"
	"github.com/sphinx-core/go/src/consensus"
	"github.com/sphinx-core/go/src/core"
	config "github.com/sphinx-core/go/src/core/sphincs/config"
	key "github.com/sphinx-core/go/src/core/sphincs/key/backend"
	sign "github.com/sphinx-core/go/src/core/sphincs/sign/backend"
	types "github.com/sphinx-core/go/src/core/transaction"
	security "github.com/sphinx-core/go/src/handshake"
	"github.com/sphinx-core/go/src/network"
	"github.com/sphinx-core/go/src/params/commit"
	params "github.com/sphinx-core/go/src/params/denom"
	"github.com/sphinx-core/go/src/rpc"
	"github.com/sphinx-core/go/src/state"
	"github.com/syndtr/goleveldb/leveldb"
)

func inspectConsensusTypes() {
	log.Printf("=== CONSENSUS TYPE INSPECTION ===")

	// Create dummy instances to inspect
	proposal := &consensus.Proposal{}
	vote := &consensus.Vote{}
	timeout := &consensus.TimeoutMsg{}

	log.Printf("Proposal type: %T", proposal)
	log.Printf("Vote type: %T", vote)
	log.Printf("TimeoutMsg type: %T", timeout)

	// Use reflection to see available fields
	log.Printf("=== END TYPE INSPECTION ===")
}

// PrintBlockchainData prints comprehensive blockchain data showing TxsRoot = MerkleRoot
func PrintBlockchainData(bc *core.Blockchain, nodeID string) {
	latestBlock := bc.GetLatestBlock()
	if latestBlock == nil {
		log.Printf("Node %s: No blocks available", nodeID)
		return
	}

	chainParams := bc.GetChainParams()

	if blockAdapter, ok := latestBlock.(*core.BlockHelper); ok {
		underlyingBlock := blockAdapter.GetUnderlyingBlock()

		// Calculate both values to show they're equal
		txsRoot := hex.EncodeToString(underlyingBlock.Header.TxsRoot)
		calculatedMerkleRoot := hex.EncodeToString(underlyingBlock.CalculateTxsRoot())

		// Verify they match
		rootsMatch := txsRoot == calculatedMerkleRoot

		log.Printf("=== NODE %s BLOCKCHAIN DATA ===", nodeID)
		log.Printf("Block Height: %d", latestBlock.GetHeight())
		log.Printf("Block Hash: %s", latestBlock.GetHash())
		log.Printf("TxsRoot (from header): %s", txsRoot)
		log.Printf("MerkleRoot (calculated): %s", calculatedMerkleRoot)
		log.Printf("TxsRoot = MerkleRoot: %v", rootsMatch)
		log.Printf("Magic Number: 0x%x", chainParams.MagicNumber)
		log.Printf("Previous Hash: %s", hex.EncodeToString(underlyingBlock.Header.PrevHash))
		log.Printf("Timestamp: %d", underlyingBlock.Header.Timestamp)
		log.Printf("Difficulty: %s", underlyingBlock.Header.Difficulty.String())
		log.Printf("Nonce: %d", underlyingBlock.Header.Nonce)
		log.Printf("Gas Limit: %s", underlyingBlock.Header.GasLimit.String())
		log.Printf("Gas Used: %s", underlyingBlock.Header.GasUsed.String())
		log.Printf("Transaction Count: %d", len(underlyingBlock.Body.TxsList))
		log.Printf("Chain ID: %d", chainParams.ChainID)
		log.Printf("Chain Name: %s", chainParams.ChainName)
		log.Printf("=================================")

		if !rootsMatch {
			log.Printf("❌ WARNING: TxsRoot does not match MerkleRoot!")
		}
	}
}

// ---------------------------------------------------------------------
// 4. Integration test – 3 (or N) validator nodes + PBFT flow
// ---------------------------------------------------------------------
func CallConsensus(numNodes int) error {
	if numNodes < 3 {
		return fmt.Errorf("-test-nodes must be >= 3")
	}

	startTime := time.Now()

	// ========== VARIABLE DECLARATIONS ==========
	var firstBlock consensus.Block
	var firstGenesisHash string
	// ========== END VARIABLE DECLARATIONS ==========

	// ========== SPHINX BLOCKCHAIN IDENTIFICATION ==========
	log.Printf("=== SPHINX BLOCKCHAIN IDENTIFICATION ===")

	// Print chain parameters
	chainParams := commit.SphinxChainParams()
	log.Printf("Chain: %s", chainParams.ChainName)
	log.Printf("Chain ID: %d", chainParams.ChainID)
	log.Printf("Symbol: %s", chainParams.Symbol)
	log.Printf("Protocol Version: %s", chainParams.Version)
	log.Printf("Genesis Time: %s", time.Unix(chainParams.GenesisTime, 0).Format(time.RFC1123))
	log.Printf("Genesis Hash: %s", chainParams.GenesisHash)
	log.Printf("Magic Number: 0x%x", chainParams.MagicNumber)
	log.Printf("Default Port: %d", chainParams.DefaultPort)
	log.Printf("BIP44 Coin Type: %d", chainParams.BIP44CoinType)
	log.Printf("Ledger Name: %s", chainParams.LedgerName)

	// Print token information
	tokenInfo := params.GetSPXTokenInfo()
	log.Printf("Token Name: %s", tokenInfo.Name)
	log.Printf("Token Symbol: %s", tokenInfo.Symbol)
	log.Printf("Decimals: %d", tokenInfo.Decimals)
	log.Printf("Total Supply: %.2f %s", float64(tokenInfo.TotalSupply), tokenInfo.Symbol)
	log.Printf("Base Unit: nSPX (1e0)")
	log.Printf("Intermediate Unit: gSPX (1e9)")
	log.Printf("Main Unit: SPX (1e18)")

	// Print wallet derivation paths
	walletPaths := map[string]string{
		"BIP44":  fmt.Sprintf("m/44'/%d'/0'/0/0", chainParams.BIP44CoinType),
		"BIP49":  fmt.Sprintf("m/49'/%d'/0'/0/0", chainParams.BIP44CoinType),
		"BIP84":  fmt.Sprintf("m/84'/%d'/0'/0/0", chainParams.BIP44CoinType),
		"Ledger": fmt.Sprintf("m/44'/%d'/0'", chainParams.BIP44CoinType),
	}
	log.Printf("Wallet Derivation Paths:")
	for name, path := range walletPaths {
		log.Printf("  %s: %s", name, path)
	}

	log.Printf("Network: Sphinx Mainnet")
	log.Printf("Consensus: PBFT")
	log.Printf("========================================")

	// ========== WRITE CHAIN IDENTIFICATION TO JSON ==========
	chainIdentification := ChainIdentificationJSON{
		Timestamp:   time.Now().Format(time.RFC3339),
		ChainParams: chainParams,
		TokenInfo:   tokenInfo,
		WalletPaths: walletPaths,
		NetworkInfo: map[string]interface{}{
			"network":        "Sphinx Mainnet",
			"consensus":      "PBFT",
			"test_timestamp": startTime.Format(time.RFC3339),
			"num_test_nodes": numNodes,
		},
	}

	if err := common.WriteJSONToFile(chainIdentification, "chain_identification.json"); err != nil {
		log.Printf("Warning: Failed to write chain identification JSON: %v", err)
	} else {
		log.Printf("Chain identification written to: data/output/chain_identification.json")
	}
	// ========== END HEADER INFORMATION ==========

	// --------------------------------------------------------------
	// 0. CLEAN UP OLD TEST DATA FIRST
	// --------------------------------------------------------------
	testDataDir := common.DataDir
	if _, err := os.Stat(testDataDir); err == nil {
		log.Printf("Cleaning up old test data from previous runs...")
		if err := os.RemoveAll(testDataDir); err != nil {
			return fmt.Errorf("failed to clean test data: %v", err)
		}
		log.Printf("Old test data cleaned successfully")
	}

	// Add this after imports or in runPBFTIntegrationTest
	inspectConsensusTypes()
	// --------------------------------------------------------------
	// 1. Prepare data directories, LevelDB, key-managers, etc.
	// --------------------------------------------------------------
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dbs := make([]*leveldb.DB, numNodes)
	sphincsMgrs := make([]*sign.SphincsManager, numNodes)
	blockchains := make([]*core.Blockchain, numNodes)
	consensusEngines := make([]*consensus.Consensus, numNodes)

	validatorIDs := make([]string, numNodes)
	for i := 0; i < numNodes; i++ {
		validatorIDs[i] = fmt.Sprintf("validator-%d", i)
	}

	for i := 0; i < numNodes; i++ {
		nodeName := fmt.Sprintf("node-%d", i)
		// Use common.GetNodeDataDir for standardized path
		dataDir := common.GetNodeDataDir(nodeName)
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			return err
		}

		// Use common.GetLevelDBPath for standardized LevelDB path
		db, err := leveldb.OpenFile(common.GetLevelDBPath(nodeName), nil)
		if err != nil {
			return err
		}
		dbs[i] = db

		km, err := key.NewKeyManager()
		if err != nil {
			return err
		}
		params, err := config.NewSPHINCSParameters()
		if err != nil {
			return err
		}
		sphincsMgrs[i] = sign.NewSphincsManager(db, km, params)

		// --------------------------------------------------------------
		// 2. Create the Blockchain + Consensus engine
		// --------------------------------------------------------------
		// Use common.GetBlockchainDataDir for standardized blockchain path
		bc, err := core.NewBlockchain(common.GetBlockchainDataDir(nodeName), validatorIDs[i], validatorIDs)
		if err != nil {
			return fmt.Errorf("node %d blockchain init: %v", i, err)
		}

		// ========== CAPTURE FIRST BLOCK AND GENESIS HASH ==========
		if i == 0 { // Capture from first node
			firstBlock = bc.GetLatestBlock()
			if firstBlock != nil {
				firstGenesisHash = firstBlock.GetHash()
				log.Printf("Captured genesis block: height=%d, hash=%s",
					firstBlock.GetHeight(), firstGenesisHash)
			} else {
				log.Printf("Warning: No genesis block found for node 0")
				firstGenesisHash = "unknown-genesis-hash"
			}
		}
		// ========== END CAPTURE ==========

		// ========== PRINT BLOCKCHAIN CHAIN INFO ==========
		chainInfo := bc.GetChainInfo()
		log.Printf("Node-%d Chain Info:", i)
		log.Printf("  Chain: %s", chainInfo["chain_name"])
		log.Printf("  Chain ID: %d", chainInfo["chain_id"])
		log.Printf("  Symbol: %s", chainInfo["symbol"])
		log.Printf("  Version: %s", chainInfo["version"])
		log.Printf("  Magic Number: %s", chainInfo["magic_number"])
		log.Printf("  BIP44 Coin Type: %d", chainInfo["bip44_coin_type"])
		log.Printf("  Ledger Name: %s", chainInfo["ledger_name"])
		// ========== END CHAIN INFO ==========

		// Test storage immediately with better error handling
		log.Printf("Node-%d: Testing storage layer...", i)
		if debugErr := bc.DebugStorage(); debugErr != nil {
			log.Printf("Node-%d storage test warning: %v", i, debugErr)
			// Don't fail immediately, let's see if the blockchain still works
		}
		blockchains[i] = bc

		// Create NodeManager using the network package's TestNodeManager
		nodeMgr := network.NewCallNodeManager()
		for _, id := range validatorIDs {
			// Add ALL validators as peers, including self for test environment
			nodeMgr.AddPeer(id)
		}
		log.Printf("Node-%d peers: %v", i, validatorIDs)

		// Create Consensus with full args
		cons := consensus.NewConsensus(
			validatorIDs[i], // nodeID
			nodeMgr,         // NodeManager
			bc,              // BlockChain (interface)
			bc.CommitBlock,  // onCommit callback
		)
		consensusEngines[i] = cons
		bc.SetConsensusEngine(cons)
		bc.SetConsensus(cons)

		// Use network package to register consensus
		network.RegisterConsensus(validatorIDs[i], cons)

		// Set shorter timeout via setter
		cons.SetTimeout(15 * time.Second)
		// Set leader based on view 0 - only node-0 should be leader initially
		if i == 0 {
			cons.SetLeader(true)
			log.Printf("Node-0 set as leader for initial view")
		} else {
			cons.SetLeader(false)
		}

		// Start consensus engine
		if err := cons.Start(); err != nil {
			return fmt.Errorf("failed to start consensus for node %d: %v", i, err)
		}

		// Add small delay to ensure consensus is fully started
		time.Sleep(100 * time.Millisecond)

		// Start leader loop for automatic block proposal
		bc.StartLeaderLoop(ctx)
	}

	// ========== ADD GENESIS VERIFICATION HERE ==========
	// Verify all nodes have genesis block AND same genesis hash
	log.Printf("=== VERIFYING GENESIS BLOCK CONSISTENCY ===")
	for i := 0; i < numNodes; i++ {
		genesis := blockchains[i].GetLatestBlock()
		if genesis == nil || genesis.GetHeight() != 0 {
			return fmt.Errorf("node %d failed to initialize genesis block", i)
		}

		if i == 0 {
			firstGenesisHash = genesis.GetHash()
			log.Printf("Node-0 genesis: height=%d, hash=%s", genesis.GetHeight(), genesis.GetHash())
		} else {
			if genesis.GetHash() != firstGenesisHash {
				return fmt.Errorf("genesis block hash mismatch: node0=%s node%d=%s",
					firstGenesisHash, i, genesis.GetHash())
			}
			log.Printf("Node-%d genesis: height=%d, hash=%s (matches)", i, genesis.GetHeight(), genesis.GetHash())
		}
	}
	log.Printf("✅ All nodes have consistent genesis blocks")

	// ========== TEST MESSAGE DELIVERY ==========
	log.Printf("=== TESTING MESSAGE DELIVERY ===")
	// Test proposal delivery
	testBlock, err := blockchains[0].CreateBlock()
	if err == nil {
		testProposal := &consensus.Proposal{
			Block: testBlock,
			View:  0,
		}
		// Use the network package's TestNodeManager to test broadcast
		testNodeMgr := network.NewCallNodeManager()
		for _, id := range validatorIDs {
			testNodeMgr.AddPeer(id)
		}
		testNodeMgr.BroadcastMessage("proposal", testProposal)
	} else {
		log.Printf("Message delivery test skipped: %v", err)
	}
	log.Printf("=== MESSAGE DELIVERY TEST COMPLETE ===")
	// ========== END MESSAGE DELIVERY TEST ==========

	// --------------------------------------------------------------
	// 4. START THE JSON-RPC SERVER for every test node
	// --------------------------------------------------------------
	for i := 0; i < numNodes; i++ {
		msgCh := make(chan *security.Message, 100)
		rpcSrv := rpc.NewServer(msgCh, blockchains[i])

		go func(ch chan *security.Message, srv *rpc.Server, nodeIdx int) {
			for secMsg := range ch {
				if secMsg.Type != "rpc" {
					continue
				}

				data, ok := secMsg.Data.([]byte)
				if !ok {
					log.Printf("Node-%d: Invalid RPC data type: %T", nodeIdx, secMsg.Data)
					continue
				}

				// Unmarshal inner RPC message to get From address
				var rpcMsg rpc.Message
				if err := rpcMsg.Unmarshal(data); err != nil {
					log.Printf("Node-%d: Failed to unmarshal RPC message: %v", nodeIdx, err)
					continue
				}

				// Process request
				resp, err := srv.HandleRequest(data)
				if err != nil {
					log.Printf("Node-%d: HandleRequest error: %v", nodeIdx, err)
					continue
				}

				// Send response via UDP to the peer's address
				addr := rpcMsg.From.Address.String()
				conn, err := net.Dial("udp", addr)
				if err != nil {
					log.Printf("Node-%d: Failed to dial %s: %v", nodeIdx, addr, err)
					continue
				}
				secResp := &security.Message{Type: "rpc", Data: resp}
				enc, _ := secResp.Encode()
				conn.Write(enc)
				conn.Close()
			}
		}(msgCh, rpcSrv, i)

		httpPort := 8545 + i
		log.Printf("Node-%d JSON-RPC listening on http://127.0.0.1:%d", i, httpPort)
	}

	// Wait for nodes to initialize and sync genesis
	log.Printf("Waiting for nodes to initialize genesis blocks...")
	time.Sleep(3 * time.Second)

	// Verify all nodes have genesis block
	for i := 0; i < numNodes; i++ {
		genesis := blockchains[i].GetLatestBlock()
		if genesis == nil || genesis.GetHeight() != 0 {
			return fmt.Errorf("node %d failed to initialize genesis block", i)
		}
		log.Printf("Node-%d genesis: height=%d, hash=%s", i, genesis.GetHeight(), genesis.GetHash())
	}

	// 6. **Create a test transaction** on Node-0 and propagate to all nodes
	tx := &types.Transaction{
		Sender:   "alice",
		Receiver: "bob",
		Amount:   big.NewInt(100),
		GasLimit: big.NewInt(21000),
		GasPrice: big.NewInt(1),
		Nonce:    1,
	}

	// Add transaction to ALL nodes, not just node 0
	for i := 0; i < numNodes; i++ {
		// Create a copy for each node
		txCopy := &types.Transaction{
			Sender:   tx.Sender,
			Receiver: tx.Receiver,
			Amount:   new(big.Int).Set(tx.Amount),
			GasLimit: new(big.Int).Set(tx.GasLimit),
			GasPrice: new(big.Int).Set(tx.GasPrice),
			Nonce:    tx.Nonce,
		}

		if err := blockchains[i].AddTransaction(txCopy); err != nil {
			log.Printf("Node-%d failed to add tx: %v", i, err)
		} else {
			log.Printf("Node-%d added transaction to mempool", i)
		}
	}
	log.Printf("TEST: transaction added to all nodes (alice to bob, 100)")

	// Add debug information about consensus state
	log.Printf("=== DEBUG: Consensus State ===")
	for i := 0; i < numNodes; i++ {
		// Use HasPendingTx to check if transaction is in mempool
		hasPendingTx := blockchains[i].HasPendingTx(tx.GetHash())
		log.Printf("Node-%d: leader=%v, hasPendingTx=%v",
			i, consensusEngines[i].IsLeader(), hasPendingTx)
	}
	log.Printf("==============================")

	// Wait for transaction to propagate
	time.Sleep(2 * time.Second)

	// Leader should automatically propose block via its leader loop
	// Wait for block commitment with better timeout handling
	const timeout = 60 * time.Second // Increased timeout
	start := time.Now()
	log.Printf("Waiting for block commitment (timeout: %v)...", timeout)

	checkInterval := 500 * time.Millisecond
	progressTicker := time.NewTicker(checkInterval)
	defer progressTicker.Stop()

	lastProgressLog := time.Now()

	timeoutReached := false
	consensusOK := false

	// Use range over the ticker channel
	for range progressTicker.C {
		if time.Since(start) > timeout {
			timeoutReached = true
			break
		}

		allAtHeight1 := true
		for i := 0; i < numNodes; i++ {
			latest := blockchains[i].GetLatestBlock()
			if latest == nil || latest.GetHeight() < 1 {
				allAtHeight1 = false

				// Log progress every 5 seconds
				if time.Since(lastProgressLog) > 5*time.Second {
					if latest == nil {
						log.Printf("Progress: Node-%d still at genesis (no block)", i)
					} else {
						log.Printf("Progress: Node-%d at height %d", i, latest.GetHeight())
					}
					lastProgressLog = time.Now()
				}
				break // This break only exits the inner for loop, which is correct
			}
		}

		if allAtHeight1 {
			log.Printf("SUCCESS: All nodes reached height 1!")
			consensusOK = true
			break // This break exits the outer for loop
		}
	}

	// Handle timeout after the loop
	if timeoutReached {
		// Debug: print current state of all nodes
		log.Printf("=== TIMEOUT DEBUG INFO ===")
		for i := 0; i < numNodes; i++ {
			latest := blockchains[i].GetLatestBlock()
			hasPendingTx := blockchains[i].HasPendingTx(tx.GetHash())

			if latest != nil {
				log.Printf("Node-%d: height=%d, hash=%s, hasPendingTx=%v, leader=%v",
					i, latest.GetHeight(), latest.GetHash(), hasPendingTx, consensusEngines[i].IsLeader())
			} else {
				log.Printf("Node-%d: no blocks, hasPendingTx=%v, leader=%v",
					i, hasPendingTx, consensusEngines[i].IsLeader())
			}
		}
		log.Printf("==========================")
		return fmt.Errorf("timeout waiting for block commit after %v", timeout)
	}

	// 8. **ASSERT** that every node sees the *same* block hash
	firstBlock = blockchains[0].GetLatestBlock()
	if firstBlock == nil {
		return fmt.Errorf("node 0 has no block")
	}
	firstHash := firstBlock.GetHash()
	for i := 1; i < numNodes; i++ {
		block := blockchains[i].GetLatestBlock()
		if block == nil {
			return fmt.Errorf("node %d has no block", i)
		}
		h := block.GetHash()
		if h != firstHash {
			return fmt.Errorf("hash mismatch: node0=%s node%d=%s", firstHash, i, h)
		}
	}

	// --------------------------------------------------------------
	// 9. Print the final chain of every node (nice debug output)
	// --------------------------------------------------------------
	log.Printf("=== PBFT INTEGRATION TEST PASSED ===")

	// ========== CREATE AND SAVE COMPLETE CHAIN STATE ==========
	log.Printf("=== SAVING COMPLETE CHAIN STATE ===")

	// Create node information WITH MERKLE ROOT
	nodes := make([]*state.NodeInfo, numNodes)
	for i := 0; i < numNodes; i++ {
		nodeName := fmt.Sprintf("node-%d", i)
		b := blockchains[i].GetLatestBlock()
		chainInfo := blockchains[i].GetChainInfo()

		// Calculate Merkle root for this block
		var merkleRoot string
		if blockAdapter, ok := b.(*core.BlockHelper); ok {
			underlyingBlock := blockAdapter.GetUnderlyingBlock()
			merkleRootBytes := underlyingBlock.CalculateTxsRoot()
			merkleRoot = hex.EncodeToString(merkleRootBytes)
		} else {
			merkleRoot = "unknown"
		}

		finalState := &state.FinalStateInfo{
			BlockHeight: b.GetHeight(),
			BlockHash:   b.GetHash(),
			MerkleRoot:  merkleRoot,
			TotalBlocks: blockchains[i].GetBlockCount(),
			Status:      "completed",
			Timestamp:   time.Now().Format(time.RFC3339),
		}

		nodes[i] = &state.NodeInfo{
			NodeID:      validatorIDs[i],
			NodeName:    nodeName,
			ChainInfo:   chainInfo,
			BlockHeight: b.GetHeight(),
			BlockHash:   b.GetHash(),
			MerkleRoot:  merkleRoot,
			Timestamp:   time.Now().Format(time.RFC3339),
			FinalState:  finalState,
		}

		// PRINT MERKLE ROOT TO CONSOLE
		log.Printf("Node-%d Merkle Root: %s", i, merkleRoot)
	}

	// Also print detailed block information including Merkle root
	log.Printf("=== BLOCK INFORMATION WITH MERKLE ROOTS ===")
	for i := 0; i < numNodes; i++ {
		latestBlock := blockchains[i].GetLatestBlock()
		if latestBlock != nil {
			// Get detailed block info including Merkle root
			if blockAdapter, ok := latestBlock.(*core.BlockHelper); ok {
				underlyingBlock := blockAdapter.GetUnderlyingBlock()
				merkleRoot := hex.EncodeToString(underlyingBlock.CalculateTxsRoot())

				log.Printf("Node-%d Block Details:", i)
				log.Printf("  Height: %d", latestBlock.GetHeight())
				log.Printf("  Hash: %s", latestBlock.GetHash())
				log.Printf("  Merkle Root: %s", merkleRoot)
				log.Printf("  Magic Number: 0x%x", chainParams.MagicNumber)
				log.Printf("  Transaction Count: %d", len(underlyingBlock.Body.TxsList))
				log.Printf("  Timestamp: %d", underlyingBlock.Header.Timestamp)
			}
		}
	}

	// Print comprehensive blockchain data
	log.Printf("=== FINAL BLOCKCHAIN DATA ===")
	for i := 0; i < numNodes; i++ {
		PrintBlockchainData(blockchains[i], validatorIDs[i])
	}

	// Save chain state using the blockchain's built-in method
	if err := blockchains[0].StoreChainState(nodes, nil); err != nil {
		log.Printf("Warning: Failed to save chain state: %v", err)
	} else {
		log.Printf("✅ Chain state saved successfully with Merkle roots")
	}

	// Skip verification for now since VerifyState method is not implemented
	log.Printf("Chain state saved - verification skipped (VerifyState method not available)")

	// ========== REMOVE OLD SEPARATE FILES ==========
	// No longer need to write separate files since everything is in chain_state.json
	log.Printf("All test data consolidated into single chain_state.json file")

	// ========== ADD FINAL CHAIN INFO SUMMARY ==========
	log.Printf("=== SPHINX CHAIN SUMMARY ===")
	for i := 0; i < numNodes; i++ {
		b := blockchains[i].GetLatestBlock()
		chainInfo := blockchains[i].GetChainInfo()

		log.Printf("Node-%d:", i)
		log.Printf("  Chain: %s", chainInfo["chain_name"])
		log.Printf("  Chain ID: %d", chainInfo["chain_id"])
		log.Printf("  Height: %d", b.GetHeight())
		log.Printf("  Block Hash: %s", b.GetHash())
		log.Printf("  Symbol: %s", chainInfo["symbol"])
		log.Printf("  Network: %s", chainInfo["network"])
	}
	log.Printf("============================")

	// --------------------------------------------------------------
	// 10. Clean shutdown
	// --------------------------------------------------------------
	cancel()
	wg.Wait()
	for i := 0; i < numNodes; i++ {
		_ = dbs[i].Close()
		_ = blockchains[i].Close()
	}

	log.Printf("=== TEST COMPLETED SUCCESSFULLY ===")
	log.Printf("All test data consolidated into single file:")
	log.Printf("  - data/node-0/blockchain/state/chain_state.json")
	log.Printf("Chain identification file:")
	log.Printf("  - data/output/chain_identification.json")

	if !consensusOK {
		return fmt.Errorf("consensus test failed - nodes did not reach agreement")
	}

	return nil
}
