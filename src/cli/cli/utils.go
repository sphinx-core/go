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

// go/src/cli/cli/utils.go
package cli

import (
	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
	"github.com/sphinx-core/go/src/consensus"
	logger "github.com/sphinx-core/go/src/log"
)

// Add this function to exchange public keys between nodes
// Enhanced key exchange function
func exchangePublicKeys(signingServices map[string]*consensus.SigningService, nodeIDs []string) {
	logger.Info("=== EXCHANGING PUBLIC KEYS BETWEEN %d NODES ===", len(nodeIDs))

	// First, collect all public keys
	publicKeys := make(map[string]*sphincs.SPHINCS_PK)
	for _, nodeID := range nodeIDs {
		signingService := signingServices[nodeID]
		if signingService == nil {
			logger.Warn("No signing service for node %s", nodeID)
			continue
		}

		publicKey := signingService.GetPublicKeyObject()
		if publicKey == nil {
			logger.Warn("No public key for node %s", nodeID)
			continue
		}

		publicKeys[nodeID] = publicKey
		logger.Info("Collected public key for node %s", nodeID)
	}

	// Then register all public keys with all nodes
	for _, nodeID := range nodeIDs {
		signingService := signingServices[nodeID]
		if signingService == nil {
			continue
		}

		registeredCount := 0
		for otherNodeID, publicKey := range publicKeys {
			if nodeID == otherNodeID {
				continue // Don't register our own key
			}

			signingService.RegisterPublicKey(otherNodeID, publicKey)
			registeredCount++
		}

		logger.Info("Node %s registered %d public keys", nodeID, registeredCount)
	}

	logger.Info("✅ Public key exchange completed: %d nodes exchanged keys", len(nodeIDs))
}
