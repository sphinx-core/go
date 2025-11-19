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

// go/src/core/state/types.go
// go/src/core/state/types.go
package database

import (
	"sync"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt" // Add this import
)

// DB wraps a LevelDB instance with thread safety
type DB struct {
	db    LevelDBInterface // Change to use interface instead of concrete type
	mutex sync.RWMutex
}

// LevelDBInterface defines the interface for LevelDB operations
type LevelDBInterface interface {
	Put(key []byte, value []byte, wo *opt.WriteOptions) error // Change to opt.WriteOptions
	Get(key []byte, ro *opt.ReadOptions) ([]byte, error)      // Change to opt.ReadOptions
	Delete(key []byte, wo *opt.WriteOptions) error            // Change to opt.WriteOptions
	Close() error
	Has(key []byte, ro *opt.ReadOptions) (bool, error) // Change to opt.ReadOptions
}

// Ensure leveldb.DB implements LevelDBInterface
var _ LevelDBInterface = (*leveldb.DB)(nil)

// LevelDBAdapter adapts leveldb.DB to database.DB interface
type LevelDBAdapter struct {
	db *leveldb.DB
	mu sync.RWMutex
}
