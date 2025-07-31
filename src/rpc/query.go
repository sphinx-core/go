// Copyright 2024 Lei Ni (nilei81@gmail.com)
//
// This library follows a dual licensing model -
//
// - it is licensed under the 2-clause BSD license if you have written evidence showing that you are a licensee of github.com/lni/pothos
// - otherwise, it is licensed under the GPL-2 license
//
// See the LICENSE file for details
// https://github.com/lni/dht/tree/main
//
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

// go/src/rpc/query.go
package rpc

import (
	"time"
)

// known checks if the request status is known (timeout or responded).
func (r requestStatus) known() bool {
	return r.Timeout || r.Responded
}

// NewQuery creates a new query instance.
func NewQuery(rpcID RPCID, target NodeID, onCompletion func()) *Query {
	return &Query{
		RPCID:        rpcID,
		Target:       target,
		start:        time.Now(),
		onCompletion: onCompletion,
		Requested:    make(map[NodeID]*requestStatus),
	}
}

// Pending returns the number of pending requests.
func (q *Query) Pending() int {
	return q.pending
}

// Request adds a node to the query's requested map.
func (q *Query) Request(nodeID NodeID) {
	q.Requested[nodeID] = &requestStatus{}
	q.pending++
}

// Filter filters out candidates that have already been requested.
func (q *Query) Filter(candidates []Remote) []Remote {
	result := make([]Remote, 0)
	for _, rec := range candidates {
		if _, ok := q.Requested[rec.NodeID]; !ok {
			result = append(result, rec)
		}
	}
	return result
}

// OnTimeout marks a node as timed out and decrements pending count.
func (q *Query) OnTimeout(nodeID NodeID) bool {
	if status, ok := q.Requested[nodeID]; ok {
		if !status.known() {
			status.Timeout = true
			q.pending--
			return true
		}
	}
	return false
}

// OnResponded marks a node as responded and decrements pending count.
func (q *Query) OnResponded(nodeID NodeID) bool {
	if status, ok := q.Requested[nodeID]; ok {
		if !status.known() {
			status.Responded = true
			q.pending--
			return true
		}
	}
	return false
}

// Requested adds a node to the ping's requested map.
func (p *ping) Requested(nodeID NodeID) {
	p.requested[nodeID] = struct{}{}
}

// NewQueryManager creates a new query manager.
func NewQueryManager() *QueryManager {
	return &QueryManager{
		findNode: make(map[RPCID]*Query),
		join:     make(map[RPCID]*join),
		ping:     make(map[RPCID]*ping),
		get:      make(map[RPCID]*get),
	}
}

// GetOnCompletionTask returns the onCompletion function for a query.
func (q *QueryManager) GetOnCompletionTask(rpcID RPCID) func() {
	if v, ok := q.findNode[rpcID]; ok {
		return v.onCompletion
	}
	return nil
}

// AddFindNode adds a find node query.
func (q *QueryManager) AddFindNode(rpcID RPCID, target NodeID, onCompletion func()) *Query {
	v := NewQuery(rpcID, target, onCompletion)
	q.findNode[rpcID] = v
	return v
}

// AddJoin adds a join request.
func (q *QueryManager) AddJoin(rpcID RPCID) {
	q.join[rpcID] = &join{time.Now()}
}

// AddPing adds a ping request.
func (q *QueryManager) AddPing(rpcID RPCID, target NodeID) {
	p := &ping{
		start:     time.Now(),
		requested: make(map[NodeID]struct{}),
	}
	p.Requested(target)
	q.ping[rpcID] = p
}

// AddGet adds a get request.
func (q *QueryManager) AddGet(rpcID RPCID) {
	g := &get{
		start: time.Now(),
	}
	q.get[rpcID] = g
}

// GetQuery retrieves a query by RPCID.
func (q *QueryManager) GetQuery(rpcID RPCID) (*Query, bool) {
	v, ok := q.findNode[rpcID]
	return v, ok
}

// RemoveQuery removes a query by RPCID.
func (q *QueryManager) RemoveQuery(rpcID RPCID) {
	delete(q.findNode, rpcID)
}

// IsExpectedResponse checks if a message is an expected response.
func (q *QueryManager) IsExpectedResponse(msg Message) bool {
	if msg.Query {
		return false // Not a response
	}

	switch msg.RPCType {
	case RPCPing:
		p, ok := q.ping[msg.RPCID]
		if !ok {
			return false
		}
		_, ok = p.requested[msg.From.NodeID]
		return ok

	case RPCJoin:
		_, ok := q.join[msg.RPCID]
		return ok

	case RPCFindNode:
		f, ok := q.findNode[msg.RPCID]
		if !ok {
			return false
		}
		_, ok = f.Requested[msg.From.NodeID]
		return ok

	case RPCGet, RPCStore:
		_, ok := q.get[msg.RPCID]
		return ok

	default:
		return false
	}
}

// GC performs garbage collection on expired queries.
func (q *QueryManager) GC() {
	last := time.Now().Add(-expiredInterval)
	for key, f := range q.findNode {
		if f.start.Before(last) {
			delete(q.findNode, key)
		}
	}
	for key, j := range q.join {
		if j.start.Before(last) {
			delete(q.join, key)
		}
	}
	for key, p := range q.ping {
		if p.start.Before(last) {
			delete(q.ping, key)
		}
	}
	for key, g := range q.get {
		if g.start.Before(last) {
			delete(q.get, key)
		}
	}
}
