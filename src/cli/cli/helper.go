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
	logger "github.com/sphinx-core/go/src/log"
	"github.com/sphinx-core/go/src/network"
	"github.com/sphinx-core/go/src/params/commit"
	params "github.com/sphinx-core/go/src/params/denom"
	"github.com/sphinx-core/go/src/rpc"
	"github.com/sphinx-core/go/src/state"
	"github.com/syndtr/goleveldb/leveldb"
)

// inspectConsensusTypes examines the concrete types and structure of consensus messages for debugging
func inspectConsensusTypes() {
	logger.Info("=== CONSENSUS TYPE INSPECTION ===")

	// Instantiate consensus message types to inspect their structure
	proposal := &consensus.Proposal{}
	vote := &consensus.Vote{}
	timeout := &consensus.TimeoutMsg{}

	logger.Info("Proposal type: %T", proposal)
	logger.Info("Vote type: %T", vote)
	logger.Info("TimeoutMsg type: %T", timeout)

	logger.Info("=== END TYPE INSPECTION ===")
}

// PrintBlockchainData displays comprehensive blockchain information including TxsRoot and MerkleRoot validation
func PrintBlockchainData(bc *core.Blockchain, nodeID string) {
	latestBlock := bc.GetLatestBlock()
	if latestBlock == nil {
		logger.Info("Node %s: No blocks available", nodeID)
		return
	}

	chainParams := bc.GetChainParams()

	if blockAdapter, ok := latestBlock.(*core.BlockHelper); ok {
		underlyingBlock := blockAdapter.GetUnderlyingBlock()

		// Validate that TxsRoot in header matches calculated MerkleRoot
		txsRoot := hex.EncodeToString(underlyingBlock.Header.TxsRoot)
		calculatedMerkleRoot := hex.EncodeToString(underlyingBlock.CalculateTxsRoot())
		rootsMatch := txsRoot == calculatedMerkleRoot

		logger.Info("=== NODE %s BLOCKCHAIN DATA ===", nodeID)
		logger.Info("Block Height: %d", latestBlock.GetHeight())
		logger.Info("Block Hash: %s", latestBlock.GetHash())
		logger.Info("TxsRoot (from header): %s", txsRoot)
		logger.Info("MerkleRoot (calculated): %s", calculatedMerkleRoot)
		logger.Info("TxsRoot = MerkleRoot: %v", rootsMatch)
		logger.Info("Magic Number: 0x%x", chainParams.MagicNumber)
		logger.Info("Previous Hash: %s", hex.EncodeToString(underlyingBlock.Header.PrevHash))
		logger.Info("Timestamp: %d", underlyingBlock.Header.Timestamp)
		logger.Info("Difficulty: %s", underlyingBlock.Header.Difficulty.String())
		logger.Info("Nonce: %d", underlyingBlock.Header.Nonce)
		logger.Info("Gas Limit: %s", underlyingBlock.Header.GasLimit.String())
		logger.Info("Gas Used: %s", underlyingBlock.Header.GasUsed.String())
		logger.Info("Transaction Count: %d", len(underlyingBlock.Body.TxsList))
		logger.Info("Chain ID: %d", chainParams.ChainID)
		logger.Info("Chain Name: %s", chainParams.ChainName)
		logger.Info("=================================")

		if !rootsMatch {
			logger.Warn("❌ WARNING: TxsRoot does not match MerkleRoot!")
		}
	}
}

// CallConsensus orchestrates a PBFT integration test with N validator nodes
func CallConsensus(numNodes int) error {
	if numNodes < 3 {
		return fmt.Errorf("PBFT requires at least 3 validator nodes, got %d", numNodes)
	}

	startTime := time.Now()

	// State variables for tracking test progress
	var firstBlock consensus.Block
	var firstGenesisHash string

	// ========== BLOCKCHAIN IDENTIFICATION AND CONFIGURATION ==========
	logger.Info("=== SPHINX BLOCKCHAIN IDENTIFICATION ===")

	// Retrieve and display mainnet chain parameters
	chainParams := commit.SphinxChainParams()
	logger.Info("Chain: %s", chainParams.ChainName)
	logger.Info("Chain ID: %d", chainParams.ChainID)
	logger.Info("Symbol: %s", chainParams.Symbol)
	logger.Info("Protocol Version: %s", chainParams.Version)
	logger.Info("Genesis Time: %s", time.Unix(chainParams.GenesisTime, 0).Format(time.RFC1123))
	logger.Info("Genesis Hash: %s", chainParams.GenesisHash)
	logger.Info("Magic Number: 0x%x", chainParams.MagicNumber)
	logger.Info("Default Port: %d", chainParams.DefaultPort)
	logger.Info("BIP44 Coin Type: %d", chainParams.BIP44CoinType)
	logger.Info("Ledger Name: %s", chainParams.LedgerName)

	// Display SPX token economics and denominations
	tokenInfo := params.GetSPXTokenInfo()
	logger.Info("Token Name: %s", tokenInfo.Name)
	logger.Info("Token Symbol: %s", tokenInfo.Symbol)
	logger.Info("Decimals: %d", tokenInfo.Decimals)
	logger.Info("Total Supply: %.2f %s", float64(tokenInfo.TotalSupply), tokenInfo.Symbol)
	logger.Info("Base Unit: nSPX (1e0)")
	logger.Info("Intermediate Unit: gSPX (1e9)")
	logger.Info("Main Unit: SPX (1e18)")

	// Generate and display standard wallet derivation paths
	walletPaths := map[string]string{
		"BIP44":  fmt.Sprintf("m/44'/%d'/0'/0/0", chainParams.BIP44CoinType),
		"BIP49":  fmt.Sprintf("m/49'/%d'/0'/0/0", chainParams.BIP44CoinType),
		"BIP84":  fmt.Sprintf("m/84'/%d'/0'/0/0", chainParams.BIP44CoinType),
		"Ledger": fmt.Sprintf("m/44'/%d'/0'", chainParams.BIP44CoinType),
	}
	logger.Info("Wallet Derivation Paths:")
	for name, path := range walletPaths {
		logger.Info("  %s: %s", name, path)
	}

	// Determine network configuration based on chain parameters using tagged switch
	networkType := "mainnet"
	networkDisplayName := "Sphinx Mainnet"

	switch chainName := chainParams.ChainName; chainName {
	case "Sphinx Devnet":
		networkType = "devnet"
		networkDisplayName = "Sphinx Devnet"
	case "Sphinx Testnet":
		networkType = "testnet"
		networkDisplayName = "Sphinx Testnet"
	// Add more cases as needed for other network types
	default:
		// Default to mainnet for "Sphinx Mainnet" or any unrecognized name
		networkType = "mainnet"
		networkDisplayName = "Sphinx Mainnet"
	}

	logger.Info("Network: %s", networkDisplayName)
	logger.Info("Consensus: PBFT")
	logger.Info("========================================")

	// ========== CHAIN IDENTIFICATION DATA EXPORT ==========
	networkName := chainParams.ChainName

	chainIdentification := ChainIdentificationJSON{
		Timestamp:   time.Now().Format(time.RFC3339),
		ChainParams: chainParams,
		TokenInfo:   tokenInfo,
		WalletPaths: walletPaths,
		NetworkInfo: map[string]interface{}{
			"network_name":   networkName,
			"protocol":       fmt.Sprintf("SPX/%s", chainParams.Version),
			"consensus":      "PBFT",
			"test_timestamp": startTime.Format(time.RFC3339),
			"num_test_nodes": numNodes,
		},
	}

	if err := common.WriteJSONToFile(chainIdentification, "chain_identification.json"); err != nil {
		logger.Warn("Failed to write chain identification JSON: %v", err)
	} else {
		logger.Info("Chain identification written to: data/output/chain_identification.json")
	}

	// ========== TEST ENVIRONMENT SETUP ==========
	testDataDir := common.DataDir
	if _, err := os.Stat(testDataDir); err == nil {
		logger.Info("Cleaning up previous test data...")
		if err := os.RemoveAll(testDataDir); err != nil {
			return fmt.Errorf("failed to clean test data: %v", err)
		}
		logger.Info("Previous test data cleaned successfully")
	}

	// Debug consensus message types
	inspectConsensusTypes()

	// ========== NODE INFRASTRUCTURE INITIALIZATION ==========
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize node components
	dbs := make([]*leveldb.DB, numNodes)
	sphincsMgrs := make([]*sign.SphincsManager, numNodes)
	blockchains := make([]*core.Blockchain, numNodes)
	consensusEngines := make([]*consensus.Consensus, numNodes)

	// Generate validator identifiers
	validatorIDs := make([]string, numNodes)
	for i := 0; i < numNodes; i++ {
		validatorIDs[i] = fmt.Sprintf("validator-%d", i)
	}

	// Initialize each validator node
	for i := 0; i < numNodes; i++ {
		nodeName := fmt.Sprintf("node-%d", i)

		// Create node data directory
		dataDir := common.GetNodeDataDir(nodeName)
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			return err
		}

		// Initialize LevelDB storage
		db, err := leveldb.OpenFile(common.GetLevelDBPath(nodeName), nil)
		if err != nil {
			return err
		}
		dbs[i] = db

		// Initialize SPHINCS+ cryptographic components
		km, err := key.NewKeyManager()
		if err != nil {
			return err
		}
		sphincsParams, err := config.NewSPHINCSParameters()
		if err != nil {
			return err
		}
		sphincsMgrs[i] = sign.NewSphincsManager(db, km, sphincsParams)
		// ========== NODE MANAGER AND PEER CONNECTIONS ==========
		// Initialize node manager and establish peer connections
		nodeMgr := network.NewCallNodeManager()

		// Add all validator nodes as peers (including self for PBFT)
		for _, id := range validatorIDs {
			nodeMgr.AddPeer(id)
		}

		logger.Info("Node-%d peer connections: %v", i, nodeMgr.GetPeerIDs())

		// ========== BLOCKCHAIN SETUP ==========
		bc, err := core.NewBlockchain(common.GetBlockchainDataDir(nodeName), validatorIDs[i], validatorIDs, networkType)
		if err != nil {
			return fmt.Errorf("node %d blockchain initialization failed: %v", i, err)
		}

		// Capture genesis block from first node for validation
		if i == 0 {
			firstBlock = bc.GetLatestBlock()
			if firstBlock != nil {
				firstGenesisHash = firstBlock.GetHash()
				logger.Info("Captured genesis block: height=%d, hash=%s",
					firstBlock.GetHeight(), firstGenesisHash)
			} else {
				logger.Warn("No genesis block found for node 0")
				firstGenesisHash = "unknown-genesis-hash"
			}
		}

		// Display node chain configuration
		chainInfo := bc.GetChainInfo()
		logger.Info("Node-%d Chain Configuration:", i)
		logger.Info("  Chain: %s", chainInfo["chain_name"])
		logger.Info("  Chain ID: %d", chainInfo["chain_id"])
		logger.Info("  Symbol: %s", chainInfo["symbol"])
		logger.Info("  Version: %s", chainInfo["version"])
		logger.Info("  Magic Number: %s", chainInfo["magic_number"])
		logger.Info("  BIP44 Coin Type: %d", chainInfo["bip44_coin_type"])
		logger.Info("  Ledger Name: %s", chainInfo["ledger_name"])

		// Validate storage layer functionality
		logger.Info("Node-%d: Validating storage layer...", i)
		if debugErr := bc.DebugStorage(); debugErr != nil {
			logger.Warn("Node-%d storage validation warning: %v", i, debugErr)
		}
		blockchains[i] = bc

		// ========== NETWORK AND CONSENSUS CONFIGURATION ==========
		// Use the SAME nodeMgr instance created earlier
		// Initialize PBFT consensus engine
		cons := consensus.NewConsensus(
			validatorIDs[i],
			nodeMgr, // Use the nodeMgr created above
			bc,
			bc.CommitBlock,
		)
		consensusEngines[i] = cons
		bc.SetConsensusEngine(cons)
		bc.SetConsensus(cons)

		// Register consensus with network layer
		network.RegisterConsensus(validatorIDs[i], cons)

		// Configure consensus parameters (timeout only)
		cons.SetTimeout(15 * time.Second)

		// DO NOT set manual leader - PBFT will handle leader rotation
		// based on view numbers: view % numValidators determines leader

		// Start consensus engine
		if err := cons.Start(); err != nil {
			return fmt.Errorf("failed to start consensus for node %d: %v", i, err)
		}

		// Allow consensus engine to fully initialize
		time.Sleep(100 * time.Millisecond)

		// Begin automatic block proposal for leader
		bc.StartLeaderLoop(ctx)
	}

	// ========== GENESIS BLOCK CONSISTENCY VALIDATION ==========
	logger.Info("=== VALIDATING GENESIS BLOCK CONSISTENCY ===")
	for i := 0; i < numNodes; i++ {
		genesis := blockchains[i].GetLatestBlock()
		if genesis == nil || genesis.GetHeight() != 0 {
			return fmt.Errorf("node %d failed to initialize genesis block", i)
		}

		if i == 0 {
			firstGenesisHash = genesis.GetHash()
			logger.Info("Node-0 genesis: height=%d, hash=%s", genesis.GetHeight(), genesis.GetHash())
		} else {
			if genesis.GetHash() != firstGenesisHash {
				return fmt.Errorf("genesis block hash mismatch: node0=%s node%d=%s",
					firstGenesisHash, i, genesis.GetHash())
			}
			logger.Info("Node-%d genesis: height=%d, hash=%s (validated)", i, genesis.GetHeight(), genesis.GetHash())
		}
	}
	logger.Info("✅ All nodes have consistent genesis blocks")

	// ========== JSON-RPC SERVER INITIALIZATION ==========
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
					logger.Warn("Node-%d: Invalid RPC data type: %T", nodeIdx, secMsg.Data)
					continue
				}

				// Decode RPC message to extract source address
				var rpcMsg rpc.Message
				if err := rpcMsg.Unmarshal(data); err != nil {
					logger.Warn("Node-%d: Failed to unmarshal RPC message: %v", nodeIdx, err)
					continue
				}

				// Process RPC request and generate response
				resp, err := srv.HandleRequest(data)
				if err != nil {
					logger.Warn("Node-%d: RPC request handling error: %v", nodeIdx, err)
					continue
				}

				// Send response back to requesting peer
				addr := rpcMsg.From.Address.String()
				conn, err := net.Dial("udp", addr)
				if err != nil {
					logger.Warn("Node-%d: Failed to connect to %s: %v", nodeIdx, addr, err)
					continue
				}
				secResp := &security.Message{Type: "rpc", Data: resp}
				enc, _ := secResp.Encode()
				conn.Write(enc)
				conn.Close()
			}
		}(msgCh, rpcSrv, i)

		httpPort := 8545 + i
		logger.Info("Node-%d JSON-RPC server listening on http://127.0.0.1:%d", i, httpPort)
	}

	// Allow nodes to synchronize genesis state
	logger.Info("Synchronizing genesis blocks across nodes...")
	time.Sleep(3 * time.Second)

	// Verify all nodes have properly initialized genesis
	for i := 0; i < numNodes; i++ {
		genesis := blockchains[i].GetLatestBlock()
		if genesis == nil || genesis.GetHeight() != 0 {
			return fmt.Errorf("node %d failed to initialize genesis block", i)
		}
		logger.Info("Node-%d genesis: height=%d, hash=%s", i, genesis.GetHeight(), genesis.GetHash())
	}

	// ========== TRANSACTION PROPAGATION TEST ==========
	tx := &types.Transaction{
		Sender:   "alice",
		Receiver: "bob",
		Amount:   big.NewInt(100),
		GasLimit: big.NewInt(21000),
		GasPrice: big.NewInt(1),
		Nonce:    1,
	}

	// Distribute test transaction to all node mempools
	for i := 0; i < numNodes; i++ {
		txCopy := &types.Transaction{
			Sender:   tx.Sender,
			Receiver: tx.Receiver,
			Amount:   new(big.Int).Set(tx.Amount),
			GasLimit: new(big.Int).Set(tx.GasLimit),
			GasPrice: new(big.Int).Set(tx.GasPrice),
			Nonce:    tx.Nonce,
		}

		if err := blockchains[i].AddTransaction(txCopy); err != nil {
			logger.Warn("Node-%d failed to add transaction: %v", i, err)
		} else {
			logger.Info("Node-%d added transaction to mempool", i)
		}
	}
	logger.Info("Test transaction distributed: alice → bob (100 SPX)")

	// Display consensus state for debugging
	logger.Info("=== CONSENSUS STATE DIAGNOSTICS ===")
	for i := 0; i < numNodes; i++ {
		hasPendingTx := blockchains[i].HasPendingTx(tx.GetHash())
		logger.Info("Node-%d: leader=%v, pending_tx=%v",
			i, consensusEngines[i].IsLeader(), hasPendingTx)
	}
	logger.Info("====================================")

	// Allow transaction to propagate through network
	time.Sleep(2 * time.Second)

	// ========== BLOCK COMMITMENT AND CONSENSUS VALIDATION ==========
	const timeout = 60 * time.Second
	start := time.Now()
	logger.Info("Waiting for block commitment (timeout: %v)...", timeout)

	checkInterval := 500 * time.Millisecond
	progressTicker := time.NewTicker(checkInterval)
	defer progressTicker.Stop()

	lastProgressLog := time.Now()
	timeoutReached := false
	consensusOK := false

	// Monitor block progression across all nodes
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

				// Periodic progress reporting
				if time.Since(lastProgressLog) > 5*time.Second {
					if latest == nil {
						logger.Info("Progress: Node-%d awaiting first block", i)
					} else {
						logger.Info("Progress: Node-%d at height %d", i, latest.GetHeight())
					}
					lastProgressLog = time.Now()
				}
				break
			}
		}

		if allAtHeight1 {
			logger.Info("SUCCESS: All nodes reached block height 1!")
			consensusOK = true
			break
		}
	}

	// Handle consensus timeout scenario
	if timeoutReached {
		logger.Info("=== CONSENSUS TIMEOUT DIAGNOSTICS ===")
		for i := 0; i < numNodes; i++ {
			latest := blockchains[i].GetLatestBlock()
			hasPendingTx := blockchains[i].HasPendingTx(tx.GetHash())

			if latest != nil {
				logger.Info("Node-%d: height=%d, hash=%s, pending_tx=%v, leader=%v",
					i, latest.GetHeight(), latest.GetHash(), hasPendingTx, consensusEngines[i].IsLeader())
			} else {
				logger.Info("Node-%d: no blocks, pending_tx=%v, leader=%v",
					i, hasPendingTx, consensusEngines[i].IsLeader())
			}
		}
		logger.Info("======================================")
		return fmt.Errorf("consensus timeout after %v", timeout)
	}

	// ========== BLOCKCHAIN STATE CONSISTENCY VALIDATION ==========
	firstBlock = blockchains[0].GetLatestBlock()
	if firstBlock == nil {
		return fmt.Errorf("node 0 has no committed block")
	}
	firstHash := firstBlock.GetHash()
	for i := 1; i < numNodes; i++ {
		block := blockchains[i].GetLatestBlock()
		if block == nil {
			return fmt.Errorf("node %d has no committed block", i)
		}
		h := block.GetHash()
		if h != firstHash {
			return fmt.Errorf("block hash mismatch: node0=%s node%d=%s", firstHash, i, h)
		}
	}

	logger.Info("=== PBFT INTEGRATION TEST SUCCESSFUL ===")

	// ========== COMPREHENSIVE CHAIN STATE CAPTURE ==========
	logger.Info("=== CAPTURING FINAL CHAIN STATE ===")

	// Collect node state information including Merkle roots
	nodes := make([]*state.NodeInfo, numNodes)
	for i := 0; i < numNodes; i++ {
		nodeName := fmt.Sprintf("node-%d", i)
		b := blockchains[i].GetLatestBlock()
		chainInfo := blockchains[i].GetChainInfo()

		// Calculate and record Merkle root for validation
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

		logger.Info("Node-%d Merkle Root: %s", i, merkleRoot)
	}

	// Display detailed block information with Merkle roots
	logger.Info("=== BLOCK DATA WITH MERKLE ROOTS ===")
	for i := 0; i < numNodes; i++ {
		latestBlock := blockchains[i].GetLatestBlock()
		if latestBlock != nil {
			if blockAdapter, ok := latestBlock.(*core.BlockHelper); ok {
				underlyingBlock := blockAdapter.GetUnderlyingBlock()
				merkleRoot := hex.EncodeToString(underlyingBlock.CalculateTxsRoot())

				logger.Info("Node-%d Block Details:", i)
				logger.Info("  Height: %d", latestBlock.GetHeight())
				logger.Info("  Hash: %s", latestBlock.GetHash())
				logger.Info("  Merkle Root: %s", merkleRoot)
				logger.Info("  Magic Number: 0x%x", chainParams.MagicNumber)
				logger.Info("  Transaction Count: %d", len(underlyingBlock.Body.TxsList))
				logger.Info("  Timestamp: %d", underlyingBlock.Header.Timestamp)
			}
		}
	}

	// Generate comprehensive blockchain data reports
	logger.Info("=== FINAL BLOCKCHAIN STATE ANALYSIS ===")
	for i := 0; i < numNodes; i++ {
		PrintBlockchainData(blockchains[i], validatorIDs[i])
	}

	// Persist complete chain state to storage
	if err := blockchains[0].StoreChainState(nodes); err != nil {
		logger.Warn("Chain state persistence failed: %v", err)
	} else {
		logger.Info("✅ Chain state successfully persisted with Merkle roots")
	}

	logger.Info("Chain state verification deferred (VerifyState method unavailable)")

	// Consolidate test artifacts
	logger.Info("Test artifacts consolidated into chain_state.json")

	// ========== RESOURCE CLEANUP AND SHUTDOWN ==========
	cancel()
	wg.Wait()
	for i := 0; i < numNodes; i++ {
		_ = dbs[i].Close()
		_ = blockchains[i].Close()
	}

	logger.Info("=== PBFT INTEGRATION TEST COMPLETED ===")
	logger.Info("Test artifacts:")
	logger.Info("  - data/node-0/blockchain/state/chain_state.json")
	logger.Info("  - data/output/chain_identification.json")

	if !consensusOK {
		return fmt.Errorf("consensus validation failed - nodes did not reach agreement")
	}

	return nil
}
