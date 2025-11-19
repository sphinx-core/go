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

// go/src/core/state/helper.go
package database

import (
	"sync"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

// NewLevelDBAdapter creates a new adapter that wraps a leveldb.DB
func NewLevelDBAdapter(ldb *leveldb.DB) *DB {
	adapter := &LevelDBAdapter{db: ldb}
	return &DB{
		db:    adapter, // Now this works because adapter implements LevelDBInterface
		mutex: sync.RWMutex{},
	}
}

// Put implements LevelDBInterface
func (a *LevelDBAdapter) Put(key []byte, value []byte, wo *opt.WriteOptions) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.db.Put(key, value, wo)
}

// Get implements LevelDBInterface
func (a *LevelDBAdapter) Get(key []byte, ro *opt.ReadOptions) ([]byte, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.db.Get(key, ro)
}

// Delete implements LevelDBInterface
func (a *LevelDBAdapter) Delete(key []byte, wo *opt.WriteOptions) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.db.Delete(key, wo)
}

// Has implements LevelDBInterface
func (a *LevelDBAdapter) Has(key []byte, ro *opt.ReadOptions) (bool, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.db.Has(key, ro)
}

// Close implements LevelDBInterface
func (a *LevelDBAdapter) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.db.Close()
}
