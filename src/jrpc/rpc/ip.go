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
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,q
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package rpc

import (
	"fmt"
	"log"
	"net"
)

// IP represents a simple IP structure for sending and receiving packets
type IP struct {
	Address string
}

// NewIP creates a new IP instance with the provided address
func NewIP(address string) *IP {
	return &IP{Address: address}
}

// SendPacket sends data using raw IP protocol
func (ip *IP) SendPacket(data []byte) error {
	conn, err := net.Dial("ip4:icmp", ip.Address)
	if err != nil {
		return fmt.Errorf("failed to dial IP address: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write(data)
	if err != nil {
		return fmt.Errorf("failed to send packet: %v", err)
	}
	return nil
}

// ReceivePacket listens for incoming data packets
func (ip *IP) ReceivePacket() ([]byte, error) {
	conn, err := net.ListenPacket("ip4:icmp", ip.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to listen for packets: %v", err)
	}
	defer conn.Close()

	buffer := make([]byte, 1024)
	_, addr, err := conn.ReadFrom(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to read packet: %v", err)
	}
	log.Printf("Received packet from %v\n", addr)
	return buffer, nil
}
