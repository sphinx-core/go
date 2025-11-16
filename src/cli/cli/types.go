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

package cli

import (
	"github.com/sphinx-core/go/src/params/commit"
	params "github.com/sphinx-core/go/src/params/denom"
)

// Config holds CLI configuration parameters.
type Config struct {
	configFile string
	numNodes   int
	roles      string
	tcpAddr    string
	udpPort    string
	httpPort   string
	wsPort     string
	seedNodes  string
	dataDir    string
	nodeIndex  int
}

// TestConfig holds the parameters that the test harness uses.
type TestConfig struct {
	NumNodes int // number of validator nodes to spin up (default 3)
}

// Update the ChainIdentificationJSON struct - FIXED THE TYPE ISSUE
type ChainIdentificationJSON struct {
	Timestamp   string                  `json:"timestamp"`
	ChainParams *commit.ChainParameters `json:"chain_parameters"` // Changed from commit.SphinxChainParams to *commit.ChainParameters
	TokenInfo   *params.TokenInfo       `json:"token_info"`
	WalletPaths map[string]string       `json:"wallet_derivation_paths"`
	NetworkInfo map[string]interface{}  `json:"network_info"`
}

type NodeChainInfoJSON struct {
	NodeID      string                 `json:"node_id"`
	ChainInfo   map[string]interface{} `json:"chain_info"`
	BlockHeight uint64                 `json:"block_height"`
	BlockHash   string                 `json:"block_hash"`
	Timestamp   string                 `json:"timestamp"`
}

type TestSummaryJSON struct {
	TestName      string              `json:"test_name"`
	Timestamp     string              `json:"timestamp"`
	NumNodes      int                 `json:"num_nodes"`
	TestDuration  string              `json:"test_duration"`
	Success       bool                `json:"success"`
	FinalHeight   uint64              `json:"final_height"`
	Nodes         []NodeChainInfoJSON `json:"nodes"`
	GenesisHash   string              `json:"genesis_hash"`
	ConsensusType string              `json:"consensus_type"`
}
