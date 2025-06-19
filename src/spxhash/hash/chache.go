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

// SIPS-0001 https://github.com/sphinx-core/sips/wiki/SIPS-0001

// NewLRUCache initializes a new LRU cache.
func NewLRUCache(capacity int) *LRUCache {
	return &LRUCache{
		capacity: capacity,               // Set the cache capacity
		cache:    make(map[uint64]*Node), // Initialize the cache map
	}
}

// Get retrieves a value from the cache.
func (l *LRUCache) Get(key uint64) ([]byte, bool) {
	l.mu.Lock()         // Lock the cache for concurrent access
	defer l.mu.Unlock() // Ensure the lock is released after the function completes

	if node, found := l.cache[key]; found {
		l.moveToFront(node) // Move accessed node to the front (most recently used)
		return node.value, true
	}
	return nil, false // Return nil if key is not found
}

// Put inserts a value into the cache.
func (l *LRUCache) Put(key uint64, value []byte) {
	l.mu.Lock()         // Lock the cache for concurrent access
	defer l.mu.Unlock() // Ensure the lock is released after the function completes

	if node, found := l.cache[key]; found {
		node.value = value  // Update the value if the key already exists
		l.moveToFront(node) // Move the updated node to the front
		return
	}

	// Create a new node if the key is not found
	node := &Node{key: key, value: value}
	l.cache[key] = node // Add new node to the cache

	// If the cache is empty, set head and tail to the new node
	if l.head == nil {
		l.head = node
		l.tail = node
	} else {
		node.next = l.head // Insert new node at the front of the linked list
		l.head.prev = node
		l.head = node
	}

	// Evict the least recently used item if cache exceeds capacity
	if len(l.cache) > l.capacity {
		l.evict() // Call eviction method to remove the least recently used item
	}
}

// evict removes the least recently used item from the cache.
func (l *LRUCache) evict() {
	if l.tail == nil {
		return // Do nothing if the cache is empty
	}
	delete(l.cache, l.tail.key) // Remove the least recently used key from the cache
	l.tail = l.tail.prev        // Move the tail pointer to the previous node
	if l.tail != nil {
		l.tail.next = nil // Set the next pointer of the new tail to nil
	}
}

// moveToFront moves a node to the front of the linked list.
func (l *LRUCache) moveToFront(node *Node) {
	if node == l.head {
		return // No need to move if the node is already at the front
	}
	if node.prev != nil {
		node.prev.next = node.next // Bypass the node in the linked list
	}
	if node.next != nil {
		node.next.prev = node.prev // Bypass the node in the linked list
	}
	if node == l.tail {
		l.tail = node.prev // Update the tail if the node being moved is the tail
	}
	node.prev = nil
	node.next = l.head // Move the node to the front
	l.head.prev = node
	l.head = node
}
