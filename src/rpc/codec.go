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

// go/src/rpc/codecs.go
package rpc

import (
	"encoding/binary"
	"encoding/hex"
	"net"
)

// String converts the NodeID to a hexadecimal string representation.
func (id NodeID) String() string {
	return hex.EncodeToString(id[:])
}

// PutUint64 writes a uint64 to the buffer.
func (c *Codec) PutUint64(buf []byte, v uint64) {
	binary.BigEndian.PutUint64(buf, v)
}

// Uint64 reads a uint64 from the buffer.
func (c *Codec) Uint64(buf []byte) uint64 {
	return binary.BigEndian.Uint64(buf)
}

// PutUint32 writes a uint32 to the buffer.
func (c *Codec) PutUint32(buf []byte, v uint32) {
	binary.BigEndian.PutUint32(buf, v)
}

// Uint32 reads a uint32 from the buffer.
func (c *Codec) Uint32(buf []byte) uint32 {
	return binary.BigEndian.Uint32(buf)
}

// PutUint16 writes a uint16 to the buffer.
func (c *Codec) PutUint16(buf []byte, v uint16) {
	binary.BigEndian.PutUint16(buf, v)
}

// Uint16 reads a uint16 from the buffer.
func (c *Codec) Uint16(buf []byte) uint16 {
	return binary.BigEndian.Uint16(buf)
}

// MarshalSize calculates the size needed to marshal a Remote.
func (r *Remote) MarshalSize() int {
	sz := 32                      // NodeID (256 bits)
	sz += 4 + len(r.Address.IP)   // IP size + IP
	sz += 4                       // Port
	sz += 4 + len(r.Address.Zone) // Zone size + Zone
	return sz
}

// Marshal serializes a Remote to a byte slice.
func (r *Remote) Marshal(buf []byte) ([]byte, error) {
	if len(buf) < r.MarshalSize() {
		return nil, ErrBufferTooSmall
	}
	// NodeID (256 bits)
	copy(buf[:32], r.NodeID[:])
	// Address.IP
	ipsz := len(r.Address.IP)
	codec := &Codec{}
	codec.PutUint32(buf[32:], uint32(ipsz))
	copy(buf[36:], r.Address.IP)
	// Address.Port
	codec.PutUint32(buf[36+ipsz:], uint32(r.Address.Port))
	// Address.Zone
	zonesz := len(r.Address.Zone)
	codec.PutUint32(buf[40+ipsz:], uint32(zonesz))
	copy(buf[44+ipsz:], []byte(r.Address.Zone))
	return buf[:44+ipsz+zonesz], nil
}

// Unmarshal deserializes a Remote from a byte slice.
func (r *Remote) Unmarshal(buf []byte) error {
	if len(buf) < 32 {
		return ErrBufferTooSmall
	}
	// NodeID (256 bits)
	copy(r.NodeID[:], buf[:32])
	// IP size
	codec := &Codec{}
	if len(buf[32:]) < 4 {
		return ErrBufferTooSmall
	}
	ipSize := int(codec.Uint32(buf[32:]))
	if len(buf[36:]) < ipSize {
		return ErrBufferTooSmall
	}
	ip := make([]byte, ipSize)
	copy(ip, buf[36:36+ipSize])
	r.Address = net.UDPAddr{IP: ip}
	// Port
	if len(buf[36+ipSize:]) < 4 {
		return ErrBufferTooSmall
	}
	r.Address.Port = int(codec.Uint32(buf[36+ipSize:]))
	// Zone
	if len(buf[40+ipSize:]) < 4 {
		return ErrBufferTooSmall
	}
	zoneSize := int(codec.Uint32(buf[40+ipSize:]))
	if len(buf[44+ipSize:]) < zoneSize {
		return ErrBufferTooSmall
	}
	zone := make([]byte, zoneSize)
	copy(zone, buf[44+ipSize:44+ipSize+zoneSize])
	r.Address.Zone = string(zone)
	return nil
}

// MarshalSize calculates the size needed to marshal a Message.
func (m *Message) MarshalSize() int {
	sz := 44                   // RPCType(1) + Query(1) + TTL(2) + Target(32) + RPCID(8)
	sz += m.From.MarshalSize() // From
	sz += 4                    // Nodes count
	for _, n := range m.Nodes {
		sz += n.MarshalSize()
	}
	sz += 4 // Values count
	for _, val := range m.Values {
		sz += 4 + len(val) // Size + value
	}
	sz += 1 // Iteration
	sz += 2 // Secret
	return sz
}

// Marshal serializes a Message to a byte slice.
func (m *Message) Marshal(buf []byte) ([]byte, error) {
	if len(buf) < m.MarshalSize() {
		return nil, ErrBufferTooSmall
	}
	codec := &Codec{}
	// RPCType
	buf[0] = byte(m.RPCType)
	// Query
	if m.Query {
		buf[1] = 1
	} else {
		buf[1] = 0
	}
	// TTL
	codec.PutUint16(buf[2:], m.TTL)
	// Target (256 bits)
	copy(buf[4:36], m.Target[:])
	// RPCID
	codec.PutUint64(buf[36:], uint64(m.RPCID))
	offset := 44
	// From
	b, err := m.From.Marshal(buf[offset:])
	if err != nil {
		return nil, err
	}
	offset += len(b)
	// Nodes
	codec.PutUint32(buf[offset:], uint32(len(m.Nodes)))
	offset += 4
	for _, n := range m.Nodes {
		b, err := n.Marshal(buf[offset:])
		if err != nil {
			return nil, err
		}
		offset += len(b)
	}
	// Values
	codec.PutUint32(buf[offset:], uint32(len(m.Values)))
	offset += 4
	for _, v := range m.Values {
		codec.PutUint32(buf[offset:], uint32(len(v)))
		offset += 4
		copy(buf[offset:], v)
		offset += len(v)
	}
	buf[offset] = m.Iteration
	offset += 1
	codec.PutUint16(buf[offset:], m.Secret)
	return buf[:m.MarshalSize()], nil
}

// Unmarshal deserializes a Message from a byte slice.
func (m *Message) Unmarshal(data []byte) error {
	if len(data) < 44 {
		return ErrBufferTooSmall
	}
	codec := &Codec{}
	// RPCType
	m.RPCType = RPCType(data[0])
	// Query
	m.Query = data[1] != 0
	// TTL
	m.TTL = codec.Uint16(data[2:])
	// Target (256 bits)
	copy(m.Target[:], data[4:36])
	// RPCID
	m.RPCID = RPCID(codec.Uint64(data[36:]))
	offset := 44
	// From
	rr := &Remote{}
	if err := rr.Unmarshal(data[offset:]); err != nil {
		return err
	}
	m.From = *rr
	offset += rr.MarshalSize()
	// Nodes
	if len(data[offset:]) < 4 {
		return ErrBufferTooSmall
	}
	nodesCount := int(codec.Uint32(data[offset:]))
	offset += 4
	m.Nodes = make([]Remote, 0, nodesCount)
	for i := 0; i < nodesCount; i++ {
		remote := &Remote{}
		if err := remote.Unmarshal(data[offset:]); err != nil {
			return err
		}
		offset += remote.MarshalSize()
		m.Nodes = append(m.Nodes, *remote)
	}
	// Values
	if len(data[offset:]) < 4 {
		return ErrBufferTooSmall
	}
	valuesCount := int(codec.Uint32(data[offset:]))
	offset += 4
	m.Values = make([][]byte, 0, valuesCount)
	for i := 0; i < valuesCount; i++ {
		if len(data[offset:]) < 4 {
			return ErrBufferTooSmall
		}
		sz := int(codec.Uint32(data[offset:]))
		offset += 4
		if len(data[offset:]) < sz {
			return ErrBufferTooSmall
		}
		value := make([]byte, sz)
		copy(value, data[offset:offset+sz])
		offset += sz
		m.Values = append(m.Values, value)
	}
	m.Iteration = data[offset]
	offset += 1
	m.Secret = codec.Uint16(data[offset:])
	return nil
}
