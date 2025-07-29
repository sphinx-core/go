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
	"net"
)

// Codec provides binary encoding/decoding utilities.
type Codec struct{}

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
	sz := 16                      // NodeID (High + Low)
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
	codec := &Codec{}
	// NodeID
	codec.PutUint64(buf, r.NodeID.High)
	codec.PutUint64(buf[8:], r.NodeID.Low)
	// Address.IP
	ipsz := len(r.Address.IP)
	codec.PutUint32(buf[16:], uint32(ipsz))
	copy(buf[20:], r.Address.IP)
	// Address.Port
	codec.PutUint32(buf[20+ipsz:], uint32(r.Address.Port))
	// Address.Zone
	zonesz := len(r.Address.Zone)
	codec.PutUint32(buf[24+ipsz:], uint32(zonesz))
	copy(buf[28+ipsz:], []byte(r.Address.Zone))
	return buf[:28+ipsz+zonesz], nil
}

// Unmarshal deserializes a Remote from a byte slice.
func (r *Remote) Unmarshal(buf []byte) error {
	if len(buf) < 16 {
		return ErrBufferTooSmall
	}
	codec := &Codec{}
	// NodeID
	r.NodeID.High = codec.Uint64(buf)
	r.NodeID.Low = codec.Uint64(buf[8:])
	// IP size
	if len(buf[16:]) < 4 {
		return ErrBufferTooSmall
	}
	ipSize := int(codec.Uint32(buf[16:]))
	if len(buf[20:]) < ipSize {
		return ErrBufferTooSmall
	}
	ip := make([]byte, ipSize)
	copy(ip, buf[20:20+ipSize])
	r.Address = net.UDPAddr{IP: ip}
	// Port
	if len(buf[20+ipSize:]) < 4 {
		return ErrBufferTooSmall
	}
	r.Address.Port = int(codec.Uint32(buf[20+ipSize:]))
	// Zone
	if len(buf[24+ipSize:]) < 4 {
		return ErrBufferTooSmall
	}
	zoneSize := int(codec.Uint32(buf[24+ipSize:]))
	if len(buf[28+ipSize:]) < zoneSize {
		return ErrBufferTooSmall
	}
	zone := make([]byte, zoneSize)
	copy(zone, buf[28+ipSize:28+ipSize+zoneSize])
	r.Address.Zone = string(zone)
	return nil
}

// MarshalSize calculates the size needed to marshal a Message.
func (m *Message) MarshalSize() int {
	sz := 28                   // RPCType(1) + Query(1) + TTL(2) + Target(16) + RPCID(8)
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
	// Target
	codec.PutUint64(buf[4:], m.Target.High)
	codec.PutUint64(buf[12:], m.Target.Low)
	// RPCID
	codec.PutUint64(buf[20:], uint64(m.RPCID))
	offset := 28
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
	if len(data) < 28 {
		return ErrBufferTooSmall
	}
	codec := &Codec{}
	// RPCType
	m.RPCType = RPCType(data[0])
	// Query
	m.Query = data[1] != 0
	// TTL
	m.TTL = codec.Uint16(data[2:])
	// Target
	m.Target.High = codec.Uint64(data[4:])
	m.Target.Low = codec.Uint64(data[12:])
	// RPCID
	m.RPCID = RPCID(codec.Uint64(data[20:]))
	offset := 28
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
