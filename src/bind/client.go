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

// go/src/bind/client.go
package bind

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/sphinx-core/go/src/rpc"
)

// CallNodeRPC sends an RPC request to a node identified by its name in the resources.
func CallNodeRPC(resources []NodeResources, nodeName, method string, params interface{}, ttl uint16) (interface{}, error) {
	var targetResource *NodeResources
	for _, resource := range resources {
		if resource.P2PServer.LocalNode().ID == nodeName {
			targetResource = &resource
			break
		}
	}
	if targetResource == nil {
		return nil, fmt.Errorf("node %s not found in resources", nodeName)
	}

	// Get the node's UDP address from the P2P server configuration
	node := targetResource.P2PServer.LocalNode()
	udpAddr := node.UDPPort
	if udpAddr == "" {
		return nil, fmt.Errorf("no UDP address configured for node %s", nodeName)
	}

	// Generate NodeID from the node's PublicKey (consistent with network.GenerateKademliaID)
	hash := sha256.Sum256(node.PublicKey)
	var nodeID rpc.NodeID
	copy(nodeID[:], hash[:]) // Copy the 32-byte hash directly into nodeID

	// Call RPC
	resp, err := rpc.CallRPC(udpAddr, method, params, nodeID, ttl)
	if err != nil {
		return nil, fmt.Errorf("RPC call to %s failed: %w", nodeName, err)
	}

	// Extract result from response
	if len(resp.Values) == 0 {
		return nil, fmt.Errorf("no result data in RPC response from %s", nodeName)
	}

	var result interface{}
	if err := json.Unmarshal(resp.Values[0], &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal RPC result from %s: %w", nodeName, err)
	}

	return result, nil
}
