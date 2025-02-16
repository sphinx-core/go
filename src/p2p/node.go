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

package discover

import (
	"errors"
	"net"
	"sync"
	"time"

	key "github.com/sphinx-core/go/src/core/sphincs/key/backend"
	sign "github.com/sphinx-core/go/src/core/sphincs/sign/backend"
)

// Node represents a peer in the network
type Node struct {
	ID        string
	IP        net.IP
	Port      int
	PublicKey []byte // SPHINCS public key
	SeenAt    time.Time
}

// Discovery manages peer discovery
type Discovery struct {
	Nodes map[string]*Node
	Mutex sync.Mutex
	KM    *key.KeyManager
	SM    *sign.SphincsManager
}

// NewDiscovery initializes a new Discovery module
func NewDiscovery() (*Discovery, error) {
	km, err := key.NewKeyManager()
	if err != nil {
		return nil, err
	}

	params := km.GetSPHINCSParameters()
	manager := sign.NewSphincsManager(nil, km, params) // No LevelDB used here

	return &Discovery{
		Nodes: make(map[string]*Node),
		KM:    km,
		SM:    manager,
	}, nil
}

// GenerateKeyPair creates a SPHINCS key pair
func (d *Discovery) GenerateKeyPair() ([]byte, []byte, error) {
	sk, pk, err := d.KM.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	skBytes, pkBytes, err := d.KM.SerializeKeyPair(sk, pk)
	if err != nil {
		return nil, nil, err
	}
	return skBytes, pkBytes, nil
}

// AddNode registers a new node
func (d *Discovery) AddNode(ip net.IP, port int, pubKey []byte) error {
	d.Mutex.Lock()
	defer d.Mutex.Unlock()

	id := string(pubKey) // Using raw public key bytes as ID
	if _, exists := d.Nodes[id]; exists {
		return errors.New("node already exists")
	}
	d.Nodes[id] = &Node{
		ID:        id,
		IP:        ip,
		Port:      port,
		PublicKey: pubKey,
		SeenAt:    time.Now(),
	}
	return nil
}

// GetNode retrieves a node by its ID
func (d *Discovery) GetNode(id string) (*Node, bool) {
	d.Mutex.Lock()
	defer d.Mutex.Unlock()

	n, exists := d.Nodes[id]
	return n, exists
}

// RemoveNode removes a node from the network
func (d *Discovery) RemoveNode(id string) {
	d.Mutex.Lock()
	defer d.Mutex.Unlock()
	delete(d.Nodes, id)
}

// ListNodes returns all known nodes
func (d *Discovery) ListNodes() []*Node {
	d.Mutex.Lock()
	defer d.Mutex.Unlock()

	nodes := make([]*Node, 0, len(d.Nodes))
	for _, n := range d.Nodes {
		nodes = append(nodes, n)
	}
	return nodes
}
