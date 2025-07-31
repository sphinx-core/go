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

// go/src/dht/conn.go
package dht

import (
	"errors"
	"hash/crc32"
	"net"
	"os"
	"time"

	security "github.com/sphinx-core/go/src/handshake"
	"github.com/sphinx-core/go/src/rpc"
	"go.uber.org/zap"
)

const (
	maxPacketSize int = 4096
	readTimeout       = 250 * time.Millisecond
)

func newConn(cfg Config, logger *zap.Logger) (*conn, error) {
	listener, err := net.ListenPacket(cfg.Proto, cfg.Address.String())
	if err != nil {
		return nil, err
	}

	return &conn{
		ReceivedCh: make(chan rpc.Message, 256),
		sendBuf:    make([]byte, maxPacketSize),
		recvBuf:    make([]byte, maxPacketSize),
		c:          listener.(*net.UDPConn),
		log:        logger, // Initialize logger
	}, nil
}

func (c *conn) Close() error {
	return c.c.Close()
}

func (c *conn) SendMessage(buf []byte, addr net.UDPAddr) error {
	if _, err := c.c.WriteTo(buf, &addr); err != nil {
		return err
	}
	return nil
}

func (c *conn) ReceiveMessageLoop(stopc chan struct{}) error {
	for {
		select {
		case <-stopc:
			return nil
		default:
		}
		timeout := time.Now().Add(readTimeout)
		if err := c.c.SetReadDeadline(timeout); err != nil {
			return err
		}
		n, _, err := c.c.ReadFromUDP(c.recvBuf)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		if err != nil {
			continue
		}
		// Log received message source for debugging
		// Note: Logging requires a logger; assuming one is available or can be added
		// log.Printf("Received message from %s", addr.String())
		buf, ok := verifyReceivedMessage(c.recvBuf[:n])
		if !ok {
			continue
		}
		secMsg, err := security.DecodeMessage(buf)
		if err != nil || secMsg.Type != "rpc" {
			continue
		}
		dataBytes, ok := secMsg.Data.([]byte)
		if !ok {
			continue
		}
		var msg rpc.Message
		if err := msg.Unmarshal(dataBytes); err != nil {
			continue
		}
		select {
		case <-stopc:
			return nil
		case c.ReceivedCh <- msg:
		}
	}
}

func getMessageBuf(buf []byte, msg rpc.Message) ([]byte, error) {
	msgSize := msg.MarshalSize()
	bufSize := msgSize + 8
	if bufSize > len(buf) {
		buf = make([]byte, bufSize)
	}

	codec := &rpc.Codec{}
	// tag
	buf[0] = magicNumber[0]
	buf[1] = magicNumber[1]
	// message payload size
	codec.PutUint16(buf[2:], uint16(msgSize))
	if _, err := msg.Marshal(buf[4:]); err != nil {
		return nil, err
	}
	// crc
	v := crc32.ChecksumIEEE(buf[2 : 4+msgSize])
	codec.PutUint32(buf[4+msgSize:], v)

	return buf[:bufSize], nil
}

func verifyReceivedMessage(msg []byte) ([]byte, bool) {
	if len(msg) < 8 {
		return nil, false
	}
	if msg[0] != magicNumber[0] || msg[1] != magicNumber[1] {
		return nil, false
	}
	codec := &rpc.Codec{}
	sz := int(codec.Uint16(msg[2:]))
	if len(msg) != sz+8 {
		return nil, false
	}
	v := crc32.ChecksumIEEE(msg[2 : 4+sz])
	crcMsg := codec.Uint32(msg[4+sz:])
	if v != crcMsg {
		return nil, false
	}

	return msg[4 : 4+sz], true
}
