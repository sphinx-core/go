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

// go/src/main.go
package main

import (
	"flag"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/sphinx-core/go/src/bind"
	types "github.com/sphinx-core/go/src/core/transaction"
	"github.com/sphinx-core/go/src/http"
	logger "github.com/sphinx-core/go/src/log"
	"github.com/sphinx-core/go/src/network"
)

func main() {
	logger.Init()

	addrAlice := flag.String("addrAlice", "127.0.0.1:30303", "TCP server address for Alice")
	addrBob := flag.String("addrBob", "127.0.0.1:30304", "TCP server address for Bob")
	addrCharlie := flag.String("addrCharlie", "127.0.0.1:30305", "TCP server address for Charlie")
	httpAddr := flag.String("httpAddr", "127.0.0.1:8545", "HTTP server address for Alice")
	seeds := flag.String("seeds", "127.0.0.1:30304,127.0.0.1:30305", "Comma-separated list of seed nodes")
	flag.Parse()

	var wg sync.WaitGroup
	seedList := strings.Split(*seeds, ",")

	// Define node configurations
	configs := []bind.NodeSetupConfig{
		{
			Address:   *addrAlice,
			Name:      "Alice",
			Role:      network.RoleSender,
			HTTPPort:  *httpAddr,
			WSPort:    "127.0.0.1:8546",
			SeedNodes: seedList,
		},
		{
			Address:   *addrBob,
			Name:      "Bob",
			Role:      network.RoleReceiver,
			HTTPPort:  "127.0.0.1:8547",
			WSPort:    "127.0.0.1:8548",
			SeedNodes: seedList,
		},
		{
			Address:   *addrCharlie,
			Name:      "Charlie",
			Role:      network.RoleValidator,
			HTTPPort:  "127.0.0.1:8549",
			WSPort:    "127.0.0.1:8550",
			SeedNodes: seedList,
		},
	}

	// Setup nodes and start servers
	resources, err := bind.SetupNodes(configs, &wg)
	if err != nil {
		logger.Fatalf("Failed to setup nodes: %v", err)
	}

	// Simulate a delay before submitting a transaction
	time.Sleep(5 * time.Second)

	tx := &types.Transaction{
		Sender:    "127.0.0.1:30303",
		Receiver:  "127.0.0.1:30304",
		Amount:    big.NewInt(1000),
		GasLimit:  big.NewInt(21000),
		GasPrice:  big.NewInt(1),
		Timestamp: time.Now().Unix(),
		Nonce:     1,
	}

	logger.Infof("Submitting transaction from Alice to Bob: %+v", tx)
	err = http.SubmitTransaction(*httpAddr, *tx)
	if err != nil {
		logger.Errorf("Failed to submit transaction: %v", err)
	} else {
		logger.Infof("Transaction submitted successfully! Sender: %s, Receiver: %s, Amount: %s, Nonce: %d",
			tx.Sender, tx.Receiver, tx.Amount.String(), tx.Nonce)
	}

	// Run peer pruning loop
	go func() {
		for {
			for _, res := range resources {
				res.P2PServer.NodeManager().PruneInactivePeers(30 * time.Second)
			}
			time.Sleep(10 * time.Second)
		}
	}()

	select {}
}
