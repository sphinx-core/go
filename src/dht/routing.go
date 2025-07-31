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

// go/src/dht/routing.go
package dht

import (
	"encoding/binary"
	"net"
	"sort"
	"time"

	"github.com/elliotchance/orderedmap/v2"
	"github.com/sphinx-core/go/src/network"
	"github.com/sphinx-core/go/src/rpc"
)

const (
	DefaultK       int = 16
	DefaultBits    int = 256 // Changed from 128 to 256
	staleThreshold     = 180 * time.Second
	deadThreshold      = 480 * time.Second
)

func newBucket(k int) *kBucket {
	return &kBucket{
		k:       k,
		buckets: orderedmap.NewOrderedMap[rpc.NodeID, remoteRecord](),
	}
}

func (b *kBucket) Len() int {
	return b.buckets.Len()
}

func (b *kBucket) Observe(nodeID rpc.NodeID, address net.UDPAddr) {
	rec := remoteRecord{
		remote: rpc.Remote{
			NodeID:  nodeID,
			Address: address,
		},
		lastSeen: time.Now(),
	}
	sz := b.buckets.Len()
	if sz < b.k {
		b.buckets.Set(nodeID, rec)
		return
	} else if sz == b.k {
		if _, ok := b.buckets.Get(nodeID); ok {
			b.buckets.Set(nodeID, rec)
		} else {
			if el := b.buckets.Front(); el != nil {
				b.buckets.Delete(el.Key)
				b.buckets.Set(nodeID, rec)
			} else {
				panic("el == nil")
			}
		}
	} else {
		panic("more than k elements in the bucket")
	}
}

func (b *kBucket) CopyToList(l []rpc.Remote) []rpc.Remote {
	for el := b.buckets.Front(); el != nil; el = el.Next() {
		l = append(l, el.Value.remote)
	}
	return l
}

type routingTable struct {
	k       int
	bits    int
	nodeID  rpc.NodeID
	address net.UDPAddr
	empty   []rpc.NodeID
	stale   []rpc.Remote
	buckets []*kBucket
}

func newRoutingTable(k int, bits int, selfID rpc.NodeID, addr net.UDPAddr) *routingTable {
	rt := &routingTable{
		k:       k,
		bits:    bits,
		nodeID:  selfID,
		address: addr,
		empty:   make([]rpc.NodeID, 0, bits),
		stale:   make([]rpc.Remote, 0, k*bits),
		buckets: make([]*kBucket, bits),
	}
	for i := 0; i < bits; i++ {
		rt.buckets[i] = newBucket(k)
	}
	return rt
}

func (r *routingTable) Observe(nodeID rpc.NodeID, address net.UDPAddr) {
	prefixLen := network.Key(r.nodeID).CommonPrefixLength(network.Key(nodeID))
	if prefixLen == r.bits {
		return
	}
	b := r.buckets[prefixLen]
	b.Observe(nodeID, address)
}

func (r *routingTable) InterestedNodes() []rpc.NodeID {
	empty := r.empty[:0]
	for i := 0; i < r.bits; i++ {
		if b := r.buckets[i]; b.Len() == 0 {
			v := r.getRandomInterestedNodeID(i)
			empty = append(empty, v)
		}
	}
	return empty
}

func (r *routingTable) GetStaleRemote() []rpc.Remote {
	stale := r.stale[:0]
	now := time.Now()
	for _, b := range r.buckets {
		for el := b.buckets.Front(); el != nil; el = el.Next() {
			rec := el.Value
			if now.Sub(rec.lastSeen) > staleThreshold {
				stale = append(stale, rec.remote)
			}
		}
	}
	return stale
}

func (r *routingTable) GC() {
	now := time.Now()
	for _, b := range r.buckets {
		var toRemove []rpc.NodeID
		for el := b.buckets.Front(); el != nil; el = el.Next() {
			rec := el.Value
			if now.Sub(rec.lastSeen) > deadThreshold {
				toRemove = append(toRemove, rec.remote.NodeID)
			}
		}
		for _, nodeID := range toRemove {
			b.buckets.Delete(nodeID)
		}
	}
}

func (r *routingTable) KNearest(target rpc.NodeID) []rpc.Remote {
	if network.Key(target).IsEmpty() {
		panic("empty target")
	}
	var selected []rpc.Remote
	prefixLen := network.Key(r.nodeID).CommonPrefixLength(network.Key(target))
	if prefixLen == r.bits {
		return nil
	}
	b := r.buckets[prefixLen]
	selected = b.CopyToList(selected)
	i := prefixLen - 1
	added := 0
	for i >= 0 && added < r.k {
		cur := r.buckets[i]
		added += cur.Len()
		selected = cur.CopyToList(selected)
		i--
	}
	j := prefixLen + 1
	added = 0
	for j < len(r.buckets) && added < r.k {
		cur := r.buckets[j]
		added += cur.Len()
		selected = cur.CopyToList(selected)
		j++
	}
	selected = append(selected, r.self())
	selected = sortByDistance(selected, target)
	if len(selected) <= r.k {
		return selected
	}
	return selected[:r.k]
}

func (r *routingTable) self() rpc.Remote {
	return rpc.Remote{NodeID: r.nodeID, Address: r.address}
}

func sortByDistance(selected []rpc.Remote, target rpc.NodeID) []rpc.Remote {
	sort.Slice(selected, func(x, y int) bool {
		var dx, dy network.Key
		dx.Distance(network.Key(selected[x].NodeID), network.Key(target))
		dy.Distance(network.Key(selected[y].NodeID), network.Key(target))
		return dx.Less(dy)
	})
	return selected
}

func (r *routingTable) getRandomInterestedNodeID(prefixLen int) rpc.NodeID {
	result := r.nodeID
	high := binary.BigEndian.Uint64(result[:8])
	low := binary.BigEndian.Uint64(result[16:24])
	if prefixLen <= 63 {
		pos := 63 - prefixLen
		mask := uint64(1) << pos
		high ^= mask
	} else {
		pos := 63 - (prefixLen - 64)
		mask := uint64(1) << pos
		low ^= mask
	}
	var newNodeID rpc.NodeID
	binary.BigEndian.PutUint64(newNodeID[:8], high)
	binary.BigEndian.PutUint64(newNodeID[16:24], low)
	for i := 8; i < 16; i++ {
		newNodeID[i] = result[i]
	}
	for i := 24; i < 32; i++ {
		newNodeID[i] = result[i]
	}
	return newNodeID
}
