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

// go/src/dht/types.go
package dht

import (
	"net"
	"time"

	"github.com/elliotchance/orderedmap/v2"
	"github.com/lni/goutils/syncutil"
	"github.com/sphinx-core/go/src/network"
	"github.com/sphinx-core/go/src/rpc"
	"go.uber.org/zap"
)

// DHTConfig is the config for the DHT.
type DHTConfig struct {
	Proto   string
	Address net.UDPAddr
	Routers []net.UDPAddr
	Secret  uint16
}

type Config = DHTConfig

type schedulable func()

type timeout struct {
	RPCID     rpc.RPCID
	RPCType   rpc.RPCType
	NodeID    rpc.NodeID
	Target    rpc.NodeID
	Iteration int
}

type sendReq struct {
	Msg         rpc.Message
	Addr        net.UDPAddr
	EncodedData []byte // Add field for encoded security.Message
}

type reqType int8

const (
	RequestJoin reqType = iota
	RequestPut
	RequestGet
	RequestGetFromCached
)

type request struct {
	RequestType  reqType
	Target       network.Key
	Value        []byte
	TTL          uint16
	FromCachedCh chan [][]byte
}

type DHT struct {
	cfg         Config
	self        rpc.Remote
	address     net.UDPAddr
	conn        *conn
	rt          *routingTable
	ongoing     *rpc.QueryManager
	store       *rpc.KVStore
	cached      *rpc.KVStore
	scheduledCh chan schedulable
	sendMsgCh   chan sendReq
	requestCh   chan request
	timeoutCh   chan timeout
	loopbackCh  chan rpc.Message
	lastJoin    time.Time
	lastRefill  time.Time
	stopper     *syncutil.Stopper
	log         *zap.Logger
}

type conn struct {
	ReceivedCh chan rpc.Message
	sendBuf    []byte
	recvBuf    []byte
	c          *net.UDPConn
	log        *zap.Logger // Added logger
}

type remoteRecord struct {
	remote   rpc.Remote
	lastSeen time.Time
}

type kBucket struct {
	k       int
	buckets *orderedmap.OrderedMap[rpc.NodeID, remoteRecord]
}
