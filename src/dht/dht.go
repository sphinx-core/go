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

// go/src/dht/dht.go
package dht

import (
	"math/rand"
	"net"
	"time"

	"github.com/lni/goutils/syncutil"
	security "github.com/sphinx-core/go/src/handshake"
	"github.com/sphinx-core/go/src/network"
	"github.com/sphinx-core/go/src/rpc"
	"go.uber.org/zap"
)

const (
	cachedTTL                  uint16 = 60
	ongoingManagerGCInterval          = 5 * time.Second
	storeGCInterval                   = 60 * time.Second
	staledRemotePingInterval          = 120 * time.Second
	emptyKBucketRefillInterval        = 600 * time.Second
	routingTableGCInterval            = 300 * time.Second
	defaultFindNodeTimeout            = 100 * time.Millisecond
	minDelay                          = 50 * time.Millisecond
	minJoinInterval                   = 20 * time.Millisecond
	minRefillInterval                 = 90 * time.Millisecond
	maxFindNodeIteration              = 24
)

var (
	magicNumber = [2]byte{0xEF, 0x2B}
)

func NewDHT(cfg Config, logger *zap.Logger) (*DHT, error) {
	nodeID := network.GetRandomNodeID()
	conn, err := newConn(cfg, logger) // Pass logger to newConn
	if err != nil {
		return nil, err
	}
	return &DHT{
		cfg:         cfg,
		self:        rpc.Remote{NodeID: rpc.NodeID(nodeID), Address: cfg.Address},
		address:     cfg.Address,
		conn:        conn,
		rt:          newRoutingTable(DefaultK, DefaultBits, rpc.NodeID(nodeID), cfg.Address),
		ongoing:     rpc.NewQueryManager(),
		store:       rpc.NewKVStore(),
		cached:      rpc.NewKVStore(),
		scheduledCh: make(chan schedulable, 16),
		sendMsgCh:   make(chan sendReq, 16),
		requestCh:   make(chan request, 16),
		timeoutCh:   make(chan timeout, 16),
		loopbackCh:  make(chan rpc.Message, 16),
		stopper:     syncutil.NewStopper(),
		log:         logger,
	}, nil
}

func (d *DHT) Start() error {
	d.stopper.RunWorker(func() {
		if err := d.conn.ReceiveMessageLoop(d.stopper.ShouldStop()); err != nil {
			panic(err)
		}
	})
	d.stopper.RunWorker(func() {
		d.sendMessageWorker()
	})
	d.stopper.RunWorker(func() {
		d.loop()
	})
	d.requestToJoin()
	d.schedule(time.Second, func() {
		d.requestToJoin()
	})
	return nil
}

func (d *DHT) Close() error {
	d.log.Debug("going to stop the stopper")
	d.stopper.Stop()
	d.log.Debug("stopper stopped")
	return d.conn.Close()
}

func (d *DHT) Put(key network.Key, value []byte, ttl uint16) {
	req := request{
		RequestType: RequestPut,
		Target:      key,
		Value:       value,
		TTL:         ttl,
	}
	d.request(req)
}

func (d *DHT) Get(key network.Key) {
	req := request{
		RequestType: RequestGet,
		Target:      key,
	}
	d.request(req)
}

func (d *DHT) ScheduleGet(delay time.Duration, key network.Key) {
	d.stopper.RunWorker(func() {
		timer := time.NewTicker(delay)
		defer timer.Stop()
		select {
		case <-d.stopper.ShouldStop():
		case <-timer.C:
			d.Get(key)
		}
	})
}

func (d *DHT) GetCached(key network.Key) [][]byte {
	req := request{
		RequestType:  RequestGetFromCached,
		Target:       key,
		FromCachedCh: make(chan [][]byte, 1),
	}
	d.request(req)
	select {
	case <-d.stopper.ShouldStop():
		return nil
	case v := <-req.FromCachedCh:
		return v
	}
}

func (d *DHT) sendMessageWorker() {
	for {
		select {
		case <-d.stopper.ShouldStop():
			return
		case req := <-d.sendMsgCh:
			msg := req.Msg
			msg.Secret = d.cfg.Secret
			if err := d.conn.SendMessage(req.EncodedData, req.Addr); err != nil {
				d.log.Debug("failed to send message", zap.Error(err))
			}
		}
	}
}

func (d *DHT) loop() {
	ri := time.Duration(rand.Uint64()%5000) * time.Millisecond
	storeGCTicker := time.NewTicker(storeGCInterval + ri)
	defer storeGCTicker.Stop()
	stalePingTicker := time.NewTicker(staledRemotePingInterval + ri)
	defer stalePingTicker.Stop()
	emptyKBucketRefillTicker := time.NewTicker(emptyKBucketRefillInterval + ri)
	defer emptyKBucketRefillTicker.Stop()
	routingTableGCTicker := time.NewTicker(routingTableGCInterval + ri)
	defer routingTableGCTicker.Stop()
	ongoingGCTicker := time.NewTicker(ongoingManagerGCInterval + ri)
	defer ongoingGCTicker.Stop()

	for {
		select {
		case <-d.stopper.ShouldStop():
			d.log.Debug("main loop going to return")
			return
		case msg := <-d.loopbackCh:
			d.handleMessage(msg)
		case <-storeGCTicker.C:
			d.storeGC()
		case <-ongoingGCTicker.C:
			d.log.Debug("query manager gc called")
			d.ongoing.GC()
		case fn := <-d.scheduledCh:
			fn()
		case <-routingTableGCTicker.C:
			d.routingTableGC()
		case <-emptyKBucketRefillTicker.C:
			d.refillEmptyKBucket(false)
		case <-stalePingTicker.C:
			d.pingStaleRemotes()
		case msg := <-d.conn.ReceivedCh:
			d.handleMessage(msg)
		case req := <-d.requestCh:
			d.handleRequest(req)
		case timeout := <-d.timeoutCh:
			d.handleTimeout(timeout)
		}
	}
}

func (d *DHT) request(r request) {
	select {
	case <-d.stopper.ShouldStop():
	case d.requestCh <- r:
	}
}

func (d *DHT) handleRequest(req request) {
	switch req.RequestType {
	case RequestJoin:
		d.Join() // Changed from join
	case RequestPut:
		d.put(req.Target, req.Value, req.TTL)
	case RequestGet:
		d.get(req.Target)
	case RequestGetFromCached:
		d.getFromCached(req.Target, req.FromCachedCh)
	default:
		panic("unknown request type")
	}
}

func (d *DHT) requestToJoin() {
	d.request(request{RequestType: RequestJoin})
}

func (d *DHT) pingNode(nodeID rpc.NodeID, addr net.UDPAddr) {
	msg := rpc.Message{
		RPCType: rpc.RPCPing,
		Query:   true,
		RPCID:   rpc.GetRPCID(),
		From:    d.self,
		Target:  nodeID,
	}
	d.ongoing.AddPing(msg.RPCID, nodeID)
	d.sendMessage(msg, addr)
}

// KNearest returns the k-nearest nodes to the target NodeID from the routing table.
func (d *DHT) KNearest(target rpc.NodeID) []rpc.Remote {
	return d.rt.KNearest(target)
}

// SelfNodeID returns the NodeID of the local DHT node.
func (d *DHT) SelfNodeID() rpc.NodeID {
	return d.self.NodeID
}

// Join initiates the DHT join process by sending RPCJoin messages to seed nodes.
func (d *DHT) Join() {
	if !d.allowToJoin() {
		return
	}
	rpcID := rpc.GetRPCID()
	d.ongoing.AddJoin(rpcID)
	msg := rpc.Message{
		RPCType: rpc.RPCJoin,
		Query:   true,
		RPCID:   rpcID,
		Target:  d.self.NodeID,
		From:    d.self,
	}
	for _, router := range d.cfg.Routers {
		d.sendMessage(msg, router)
	}
}

func (d *DHT) findNode(target rpc.NodeID) {
	d.doFindNode(target, nil)
}

func (d *DHT) put(target network.Key, value []byte, ttl uint16) {
	onCompletion := func() {
		d.log.Debug("find node completed for put query",
			targetField(target),
			localNodeIDField(d))
		d.putKeyValue(target, value, ttl)
	}
	d.doFindNode(rpc.NodeID(target), onCompletion)
}

func (d *DHT) get(target network.Key) {
	onCompletion := func() {
		d.log.Debug("find node completed for get query",
			targetField(target),
			localNodeIDField(d))
		d.getKeyValue(target)
	}
	d.doFindNode(rpc.NodeID(target), onCompletion)
}

func (d *DHT) getFromCached(target network.Key, ch chan [][]byte) {
	v, _ := d.cached.Get(rpc.Key(target))
	select {
	case <-d.stopper.ShouldStop():
	case ch <- v:
	}
}

func (d *DHT) putKeyValue(target network.Key, value []byte, ttl uint16) {
	msg := rpc.Message{
		RPCType: rpc.RPCStore,
		Query:   true,
		RPCID:   rpc.GetRPCID(),
		Target:  rpc.NodeID(target),
		From:    d.self,
		TTL:     ttl,
		Values:  [][]byte{value},
	}
	kn := d.rt.KNearest(rpc.NodeID(target))
	for _, rt := range kn {
		d.sendMessage(msg, rt.Address)
	}
}

func (d *DHT) getKeyValue(target network.Key) {
	rpcID := rpc.GetRPCID()
	d.ongoing.AddGet(rpcID)
	msg := rpc.Message{
		RPCType: rpc.RPCGet,
		RPCID:   rpcID,
		Query:   true,
		Target:  rpc.NodeID(target),
		From:    d.self,
	}
	kn := d.rt.KNearest(rpc.NodeID(target))
	for _, rt := range kn {
		d.sendMessage(msg, rt.Address)
	}
}

func (d *DHT) doFindNode(target rpc.NodeID, onCompletion schedulable) {
	kn := d.rt.KNearest(target)
	if len(kn) > 0 {
		rpcID := rpc.GetRPCID()
		q := d.ongoing.AddFindNode(rpcID, target, onCompletion)
		for _, rt := range kn {
			d.sendFindNodeRequest(target, rpcID, rt, 0)
			q.Request(rt.NodeID)
		}
	}
	if len(kn) < DefaultK {
		d.schedule(getRandomDelay(time.Second), func() {
			d.Join() // Changed from d.join() to d.Join()
		})
	}
}

func (d *DHT) handleMessage(msg rpc.Message) {
	if msg.Secret != d.cfg.Secret {
		return
	}
	d.rt.Observe(msg.From.NodeID, msg.From.Address)
	if msg.Query {
		d.handleQuery(msg)
		return
	}
	d.handleResponse(msg)
}

func (d *DHT) toLocalNode(addr net.UDPAddr) bool {
	return d.self.Address.IP.Equal(addr.IP) &&
		d.self.Address.Port == addr.Port &&
		d.self.Address.Zone == addr.Zone
}

func (d *DHT) sendMessage(m rpc.Message, addr net.UDPAddr) {
	verifyMessage(m)
	data, err := m.Marshal(make([]byte, m.MarshalSize()))
	if err != nil {
		d.log.Error("Failed to marshal message", zap.Error(err))
		return
	}
	secMsg := &security.Message{Type: "rpc", Data: data}
	encodedData, err := secMsg.Encode()
	if err != nil {
		d.log.Error("Failed to encode security message", zap.Error(err))
		return
	}
	req := sendReq{Addr: addr, Msg: m, EncodedData: encodedData} // Create sendReq early
	if d.toLocalNode(addr) {
		select {
		case d.loopbackCh <- m:
		default:
			d.log.Warn("loopbackCh full, dropping message")
		}
	} else {
		select {
		case d.sendMsgCh <- req:
		default:
			d.log.Warn("sendMsgCh full, dropping message")
		}
	}
}

func (d *DHT) handleQuery(msg rpc.Message) {
	switch msg.RPCType {
	case rpc.RPCPing:
		d.handlePingQuery(msg)
	case rpc.RPCJoin:
		d.handleJoinQuery(msg)
	case rpc.RPCFindNode:
		d.handleFindNodeQuery(msg)
	case rpc.RPCStore:
		d.handlePutQuery(msg)
	case rpc.RPCGet:
		d.handleGetQuery(msg)
	default:
		panic("unknown type")
	}
}

func (d *DHT) handlePutQuery(msg rpc.Message) {
	d.log.Debug("received put query",
		fromField(msg.From),
		localNodeIDField(d),
		targetField(network.Key(msg.Target)))
	if len(msg.Values) > 0 {
		d.store.Put(rpc.Key(msg.Target), msg.Values[0], msg.TTL)
	}
}

func (d *DHT) handleGetQuery(msg rpc.Message) {
	d.log.Debug("received get query",
		fromField(msg.From),
		localNodeIDField(d),
		targetField(network.Key(msg.Target)))
	values, ok := d.store.Get(rpc.Key(msg.Target))
	if !ok {
		return
	}
	batches := rpc.To4KBatches(values)
	for _, v := range batches {
		reply := rpc.Message{
			RPCType: rpc.RPCGet,
			Query:   false,
			Target:  msg.Target,
			RPCID:   msg.RPCID,
			From:    d.self,
			Values:  v,
		}
		d.sendMessage(reply, msg.From.Address)
	}
}

func (d *DHT) handleJoinQuery(msg rpc.Message) {
	d.log.Debug("received join query",
		fromField(msg.From),
		localNodeIDField(d))
	resp := rpc.Message{
		RPCType: msg.RPCType,
		Query:   false,
		RPCID:   msg.RPCID,
		From:    d.self,
		Target:  msg.Target,
		Nodes:   d.rt.KNearest(msg.Target),
	}
	d.sendMessage(resp, msg.From.Address)
}

func (d *DHT) handlePingQuery(msg rpc.Message) {
	resp := rpc.Message{
		RPCType: msg.RPCType,
		Query:   false,
		RPCID:   msg.RPCID,
		From:    d.self,
	}
	d.sendMessage(resp, msg.From.Address)
}

func (d *DHT) handleFindNodeQuery(msg rpc.Message) {
	d.log.Debug("received find node query",
		fromField(msg.From),
		localNodeIDField(d),
		targetField(network.Key(msg.Target)))
	if network.Key(msg.Target).IsEmpty() {
		panic("empty target")
	}
	kn := d.rt.KNearest(msg.Target)
	resp := rpc.Message{
		RPCType: msg.RPCType,
		Query:   false,
		RPCID:   msg.RPCID,
		From:    d.self,
		Nodes:   kn,
		Target:  msg.Target,
	}
	d.sendMessage(resp, msg.From.Address)
}

func (d *DHT) handleResponse(msg rpc.Message) {
	if !d.ongoing.IsExpectedResponse(msg) {
		return
	}
	switch msg.RPCType {
	case rpc.RPCPing:
		// nothing to do
	case rpc.RPCGet:
		d.handleGetResponse(msg)
	case rpc.RPCFindNode:
		d.handleFindNodeResponse(msg)
	case rpc.RPCJoin:
		d.handleJoinResponse(msg)
	default:
		panic("unknown type")
	}
}

func (d *DHT) handleGetResponse(msg rpc.Message) {
	for _, v := range msg.Values {
		d.cached.Put(rpc.Key(msg.Target), v, cachedTTL)
	}
}

func (d *DHT) handleFindNodeResponse(msg rpc.Message) {
	q, ok := d.ongoing.GetQuery(msg.RPCID)
	if !ok {
		return
	}
	if q.OnResponded(msg.From.NodeID) {
		for _, node := range msg.Nodes {
			d.rt.Observe(node.NodeID, node.Address)
		}
		iter := int(msg.Iteration) + 1
		d.recursiveFindNode(msg.Target, msg.RPCID, q, iter)
	}
}

func (d *DHT) handleJoinResponse(msg rpc.Message) {
	for _, node := range msg.Nodes {
		d.rt.Observe(node.NodeID, node.Address)
	}
	d.schedule(100*time.Millisecond, func() {
		d.refillEmptyKBucket(true)
	})
}

func (d *DHT) sendFindNodeRequest(target rpc.NodeID, rpcID rpc.RPCID, rt rpc.Remote, iter int) {
	if iter <= maxFindNodeIteration {
		msg := rpc.Message{
			RPCType:   rpc.RPCFindNode,
			Query:     true,
			RPCID:     rpcID,
			From:      d.self,
			Target:    target,
			Iteration: uint8(iter),
		}
		d.sendMessage(msg, rt.Address)
	}
	d.runWorker(defaultFindNodeTimeout, func() {
		timeout := timeout{
			RPCID:     rpcID,
			RPCType:   rpc.RPCFindNode,
			NodeID:    rt.NodeID,
			Target:    target,
			Iteration: iter,
		}
		select {
		case d.timeoutCh <- timeout:
		case <-d.stopper.ShouldStop():
			return
		}
	})
}

func (d *DHT) recursiveFindNode(target rpc.NodeID, rpcID rpc.RPCID, q *rpc.Query, iter int) bool {
	kn := d.rt.KNearest(target)
	kn = q.Filter(kn)
	if q.Pending() == 0 && len(kn) == 0 {
		d.onFindNodeCompleted(rpcID)
		return true
	}
	for _, rt := range kn {
		d.sendFindNodeRequest(target, rpcID, rt, iter)
		q.Request(rt.NodeID)
	}
	return false
}

func (d *DHT) onFindNodeCompleted(rpcID rpc.RPCID) {
	onCompletion := d.ongoing.GetOnCompletionTask(rpcID)
	if onCompletion != nil {
		d.schedule(0, func() {
			onCompletion()
		})
	}
	d.ongoing.RemoveQuery(rpcID)
}

func (d *DHT) handleTimeout(timeout timeout) {
	if timeout.RPCType == rpc.RPCFindNode {
		iter := timeout.Iteration + 1
		if q, ok := d.ongoing.GetQuery(timeout.RPCID); ok {
			if q.OnTimeout(timeout.NodeID) {
				d.recursiveFindNode(timeout.Target, timeout.RPCID, q, iter)
			}
		}
	}
}

func (d *DHT) pingStaleRemotes() {
	d.log.Debug("pinging staled remotes")
	staled := d.rt.GetStaleRemote()
	ms := staledRemotePingInterval.Milliseconds()
	for _, sr := range staled {
		remote := sr
		delay := time.Duration(rand.Uint64()%uint64(ms)) * time.Millisecond
		d.schedule(delay, func() {
			d.pingNode(remote.NodeID, remote.Address)
		})
	}
}

func (d *DHT) storeGC() {
	d.log.Debug("store gc called")
	d.store.GC()
	d.cached.GC()
}

func (d *DHT) routingTableGC() {
	d.log.Debug("routing table gc called")
	d.rt.GC()
}

func (d *DHT) refillEmptyKBucket(noDelay bool) {
	if !d.allowToRefill() {
		return
	}
	d.log.Debug("refilling empty kbucket")
	nodes := d.rt.InterestedNodes()
	ms := emptyKBucketRefillInterval.Milliseconds()
	for _, node := range nodes {
		n := node
		delay := time.Duration(rand.Uint64()%uint64(ms)) * time.Millisecond
		if noDelay {
			delay = minDelay
		}
		d.schedule(delay, func() {
			d.findNode(n)
		})
	}
}

func (d *DHT) allowToJoin() bool {
	if time.Since(d.lastJoin) > minJoinInterval {
		d.lastJoin = time.Now()
		return true
	}
	return false
}

func (d *DHT) allowToRefill() bool {
	if time.Since(d.lastRefill) > minRefillInterval {
		d.lastRefill = time.Now()
		return true
	}
	return false
}

func (d *DHT) schedule(delay time.Duration, fn schedulable) {
	d.doSchedule(delay, true, fn)
}

func (d *DHT) runWorker(delay time.Duration, fn schedulable) {
	d.doSchedule(delay, false, fn)
}

func (d *DHT) doSchedule(delay time.Duration, mainThread bool, fn schedulable) {
	go func() {
		if delay > 0 {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-d.stopper.ShouldStop():
				return
			}
		}
		if mainThread {
			select {
			case <-d.stopper.ShouldStop():
			case d.scheduledCh <- fn:
			}
		} else {
			fn()
		}
	}()
}

func verifyMessage(msg rpc.Message) {
	if network.Key(msg.From.NodeID).IsEmpty() {
		panic("empty from node id")
	}
	if msg.RPCID == 0 {
		panic("empty RPCID")
	}
}

func getRandomDelay(d time.Duration) time.Duration {
	ms := d.Milliseconds()
	return time.Duration(rand.Uint64()%uint64(ms)) * time.Millisecond
}

func targetField(k network.Key) zap.Field {
	return zap.String("target", k.Short())
}

func fromField(r rpc.Remote) zap.Field {
	return zap.String("from", network.Key(r.NodeID).Short())
}

func localNodeIDField(d *DHT) zap.Field {
	return zap.String("local", network.Key(d.self.NodeID).Short())
}
