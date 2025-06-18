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

// go/src/cli/main.go
package main

import (
	"flag"
	"math/big"
	"math/rand"
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
	rand.Seed(time.Now().UnixNano())
	logger.Init()

	// Define command-line flags
	numNodes := flag.Int("numNodes", 3, "Number of nodes to initialize")
	roles := flag.String("roles", "sender,receiver,validator", "Comma-separated list of node roles (sender,receiver,validator)")
	seeds := flag.String("seeds", "", "Comma-separated list of seed nodes (optional)")
	flag.Parse()

	var wg sync.WaitGroup

	// Parse roles
	roleList := strings.Split(*roles, ",")
	parsedRoles := make([]network.NodeRole, len(roleList))
	for i, r := range roleList {
		switch r {
		case "sender":
			parsedRoles[i] = network.RoleSender
		case "receiver":
			parsedRoles[i] = network.RoleReceiver
		case "validator":
			parsedRoles[i] = network.RoleValidator
		default:
			logger.Fatalf("Invalid role: %s. Must be sender, receiver, or validator", r)
		}
	}

	// Collect flag overrides
	flagOverrides := make(map[string]string)
	if *seeds != "" {
		flagOverrides["seeds"] = *seeds
	}
	// Allow per-node overrides (e.g., --tcpAddr0, --httpPort0)
	flag.Visit(func(f *flag.Flag) {
		if strings.HasPrefix(f.Name, "tcpAddr") || strings.HasPrefix(f.Name, "httpPort") || strings.HasPrefix(f.Name, "wsPort") {
			flagOverrides[f.Name] = f.Value.String()
		}
	})

	// Get node port configurations
	portConfigs, err := network.GetNodePortConfigs(*numNodes, parsedRoles, flagOverrides)
	if err != nil {
		logger.Fatalf("Failed to get node configurations: %v", err)
	}

	// Map network.NodePortConfig to bind.NodeSetupConfig
	configs := make([]bind.NodeSetupConfig, len(portConfigs))
	for i, pc := range portConfigs {
		configs[i] = bind.NodeSetupConfig{
			Address:   pc.TCPAddr,
			Name:      pc.Name,
			Role:      pc.Role,
			HTTPPort:  pc.HTTPPort,
			WSPort:    pc.WSPort,
			SeedNodes: pc.SeedNodes,
		}
	}

	// Setup nodes and start servers
	resources, err := bind.SetupNodes(configs, &wg)
	if err != nil {
		logger.Fatalf("Failed to setup nodes: %v", err)
	}

	// Simulate a delay before submitting a transaction
	time.Sleep(5 * time.Second)

	// Find sender and receiver nodes
	var senders, receivers []network.NodePortConfig
	for _, pc := range portConfigs {
		if pc.Role == network.RoleSender {
			senders = append(senders, pc)
		} else if pc.Role == network.RoleReceiver {
			receivers = append(receivers, pc)
		}
	}
	if len(senders) == 0 || len(receivers) == 0 {
		logger.Fatalf("Missing sender or receiver node")
	}
	sender := senders[rand.Intn(len(senders))]
	var senderAddr, senderHTTPPort, receiverAddr string
	senderAddr = sender.TCPAddr
	senderHTTPPort = sender.HTTPPort
	receiverAddr = receivers[rand.Intn(len(receivers))].TCPAddr

	tx := &types.Transaction{
		Sender:    senderAddr,
		Receiver:  receiverAddr,
		Amount:    big.NewInt(1000),
		GasLimit:  big.NewInt(21000),
		GasPrice:  big.NewInt(1),
		Timestamp: time.Now().Unix(),
		Nonce:     1,
	}

	logger.Infof("Submitting transaction from %s to %s: %+v", senderAddr, receiverAddr, tx)
	err = http.SubmitTransaction(senderHTTPPort, *tx)
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
