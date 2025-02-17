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
	"net"
)

// TCP represents a simple TCP structure for creating a reliable connection
type TCP struct {
	Address string
}

// NewTCP creates a new TCP instance with the provided address
func NewTCP(address string) *TCP {
	return &TCP{Address: address}
}

// Dial establishes a TCP connection to the provided address
func (tcp *TCP) Dial() (net.Conn, error) {
	conn, err := net.Dial("tcp", tcp.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to dial TCP address: %v", err)
	}
	return conn, nil
}

// Listen starts a TCP listener to accept incoming connections
func (tcp *TCP) Listen() (net.Listener, error) {
	listener, err := net.Listen("tcp", tcp.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on TCP address: %v", err)
	}
	return listener, nil
}

// SendData sends data over an established TCP connection
func (tcp *TCP) SendData(conn net.Conn, data []byte) error {
	_, err := conn.Write(data)
	if err != nil {
		return fmt.Errorf("failed to send data: %v", err)
	}
	return nil
}

// ReceiveData receives data over an established TCP connection
func (tcp *TCP) ReceiveData(conn net.Conn) ([]byte, error) {
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to receive data: %v", err)
	}
	return buffer[:n], nil
}
