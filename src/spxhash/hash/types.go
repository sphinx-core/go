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

package spxhash

import "sync"

// LRUCache is a struct for the LRU cache implementation.
type LRUCache struct {
	capacity int              // Maximum capacity of the cache
	mu       sync.Mutex       // Mutex for concurrent access
	cache    map[uint64]*Node // Maps keys to their corresponding nodes in the cache
	head     *Node            // Pointer to the most recently used node
	tail     *Node            // Pointer to the least recently used node
}

// Node is a doubly linked list node for the LRU cache.
type Node struct {
	key   uint64 // Unique key for the node
	value []byte // Value associated with the key
	prev  *Node  // Pointer to the previous node in the list
	next  *Node  // Pointer to the next node in the list
}

// SphinxHash implements hashing based on SIP-0001 draft.
type SphinxHash struct {
	bitSize      int       // Specifies the bit size of the hash (128, 256, 384, 512)
	data         []byte    // Holds the input data to be hashed
	salt         []byte    // Salt for hashing
	cache        *LRUCache // Cache to store previously computed hashes
	maxCacheSize int       // Maximum cache size
}
