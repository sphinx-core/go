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

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"io"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/sha3"
)

// SIPS-0001 https://github.com/sphinx-core/sips/wiki/SIPS-0001

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

// Define prime constants for hash calculations.
const (
	prime32  = 0x9e3779b9         // Example prime constant for 32-bit hash
	prime64  = 0x9e3779b97f4a7c15 // Example prime constant for 64-bit hash
	saltSize = 16                 // Size of salt in bytes (128 bits = 16 bytes)

	// Argon2 parameters
	// OWASP have published guidance on Argon2 at https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
	// At time of writing (Jan 2023), this says:
	// Argon2id should use one of the following configuration settings as a base minimum which includes the minimum memory size (m), the minimum number of iterations (t) and the degree of parallelism (p).
	// m=37 MiB, t=1, p=1
	// m=15 MiB, t=2, p=1
	// Both of these configuration settings are equivalent in the defense they provide. The only difference is a trade off between CPU and RAM usage.
	memory           = 64 * 1024 // Memory cost set to 64 KiB (64 * 1024 bytes) is for demonstration purpose
	iterations       = 2         // Number of iterations for Argon2id set to 2
	parallelism      = 1         // Degree of parallelism set to 1
	tagSize          = 32        // Tag size set to 256 bits (32 bytes)
	DefaultCacheSize = 100       // Default cache size for SphinxHash
)

// SphinxHash implements hashing based on SIP-0001 draft.
type SphinxHash struct {
	bitSize      int       // Specifies the bit size of the hash (128, 256, 384, 512)
	data         []byte    // Holds the input data to be hashed
	salt         []byte    // Salt for hashing
	cache        *LRUCache // Cache to store previously computed hashes
	maxCacheSize int       // Maximum cache size
}

// Generate salt using Argon2
func generateSalt(data []byte, saltSize int) []byte {
	// Use the constants for Argon2 parameters
	timeCost := uint32(iterations)    // Use the number of iterations from the constant
	memoryCost := uint32(memory)      // Use memory cost from the constant
	parallelism := uint8(parallelism) // Use parallelism from the constant

	// Argon2id (a combination of Argon2d and Argon2i) for secure hash-based salt generation
	salt := argon2.IDKey(data, data, timeCost, memoryCost, parallelism, uint32(saltSize))

	return salt
}

// NewSphinxHash creates a new SphinxHash with a specific bit size for the hash.
func NewSphinxHash(bitSize int, data []byte) *SphinxHash {
	// Pass saltSize explicitly when calling generateSalt
	salt := generateSalt(data, saltSize) // Use deterministic salt based on input data
	return &SphinxHash{
		bitSize:      bitSize,
		salt:         salt,
		cache:        NewLRUCache(DefaultCacheSize),
		maxCacheSize: DefaultCacheSize,
	}
}

// GetHash retrieves or calculates the hash of the given data.
func (s *SphinxHash) GetHash(data []byte) []byte {
	hashKey := binary.LittleEndian.Uint64(data[:8]) // Ensure the key is unique based on the data
	if cachedValue, found := s.cache.Get(hashKey); found {
		return cachedValue // Return cached value if found
	}

	// Create a new SphinxHash with the input data to get the deterministic salt
	sphinx := NewSphinxHash(s.bitSize, data) // Pass data to generate deterministic salt
	hash := sphinx.hashData(data)            // Calculate the hash using the new deterministic salt
	s.cache.Put(hashKey, hash)               // Store the calculated hash in the cache

	return hash // Return the calculated hash
}

// Read reads from the hash data into p.
func (s *SphinxHash) Read(p []byte) (n int, err error) {
	// Calculate the hash for the data stored in the SphinxHash instance
	hash := s.GetHash(s.data)

	// Copy the hash into the provided buffer p
	n = copy(p, hash)
	if n < len(hash) {
		return n, io.EOF // Return EOF if the buffer is smaller than the hash
	}
	return n, nil
}

// Write adds data to the hash.
func (s *SphinxHash) Write(p []byte) (n int, err error) {
	s.data = append(s.data, p...) // Append new data to the existing data
	return len(p), nil            // Return the number of bytes written
}

// Sum appends the current hash to b and returns the resulting slice.
func (s *SphinxHash) Sum(b []byte) []byte {
	hash := s.GetHash(s.data) // Compute the hash of the current data
	return append(b, hash...) // Append the hash to the provided byte slice
}

// Size returns the number of bytes in the hash based on the bit size.
func (s *SphinxHash) Size() int {
	switch s.bitSize {
	case 256:
		// SHA-512/256 produces a 256-bit output, equivalent to 32 bytes.
		return 32 // 256 bits = 32 bytes (SHA-512/256)
	case 384:
		// SHA-384 produces a 384-bit output, equivalent to 48 bytes.
		return 48 // 384 bits = 48 bytes (SHA-384)
	case 512:
		// SHA-512 produces a 512-bit output, equivalent to 64 bytes.
		return 64 // 512 bits = 64 bytes (SHA-512)
	default:
		// Default to 256 bits (SHA-512/256) if bitSize is unspecified
		return 32 // Default to 256 bits (SHA-512/256)
	}
}

// BlockSize returns the hash block size based on the current bit size configuration.
func (s *SphinxHash) BlockSize() int {
	switch s.bitSize {
	case 256:
		return 128 // SHA-512/256 block size is 128 bytes
	case 384:
		return 128 // SHA-384 block size is 128 bytes
	case 512:
		return 128 // SHA-512 block size is 128 bytes
	default:
		return 136 // SHAKE256 block size is 136 bytes (1088 bits)
	}
}

// hashData calculates the combined hash of data using multiple hash functions based on the bit size.
func (s *SphinxHash) hashData(data []byte) []byte {
	var sha2Hash []byte

	// Combine the input data with the salt for Argon2id.
	combined := append(data, s.salt...) // Append salt to data to strengthen the final key.
	// Key stretching using Argon2id, which is a memory-hard function to improve resistance against brute-force attacks.
	stretchedKey := argon2.IDKey(combined, s.salt, iterations, memory, parallelism, 64) // Generate a 64-byte key.

	// Step 1: Compute SHA-512/256 on the stretched key.
	hash := sha512.New512_256() // Create a new SHA-512/256 hash instance.
	hash.Write(stretchedKey)    // Hash the stretched key using SHA-512/256.
	sha2Hash = hash.Sum(nil)    // Get the resulting hash.

	// Step 2: Compute SHAKE256 (a variable-length cryptographic hash function).
	shake := sha3.NewShake256()
	shake.Write(stretchedKey) // Use the stretched key for SHAKE256.

	// Dynamically determine the length of the shake output based on the size.
	shakeLength := s.Size()                // Use the Size function to dynamically set the output length for SHAKE256.
	shakeHash := make([]byte, shakeLength) // Create a slice for the dynamically determined length.
	shake.Read(shakeHash)                  // Read the resulting hash into shakeHash.

	// Step 3: Combine both the hashes (SHA-256 and SHAKE256) using SphinxHash.
	return s.sphinxHash(sha2Hash, shakeHash, prime32) // Pass the hashes and prime constant to SphinxHash for combination.
}

// sphinxHash combines two byte slices (hash1 and hash2) using a prime constant and applies structured combinations.
// It utilizes chaining (H∘(x) = H0(H1(x))) and concatenation (H|(x) = H0(x)|H1(x)) of hash functions to enhance pre-image and collision resistance.
func (s *SphinxHash) sphinxHash(hash1, hash2 []byte, primeConstant uint64) []byte {

	// Ensure both input hashes have the same length for consistent processing.
	// This check ensures that both input hashes are compatible for further processing in the algorithm.
	if len(hash1) != len(hash2) {
		panic("hash1 and hash2 must have the same length") // Panic if the lengths are not equal.
	}

	// Step 1: Hash both input hashes to protect against pre-images.
	// This applies a chaining operation: H∘(x) = H0(H1(x)).
	// We first hash hash1 using SHA-512/256 to apply standard cryptographic resistance.
	chainHash1 := sha512.New512_256()
	chainHash1.Write(hash1)                 // Hash the first input hash using SHA-512/256.
	chainHash1Result := chainHash1.Sum(nil) // Get the result of the hash as a slice.

	// Step 2: Apply a second hash function (H0) to the result of the first hash (H1).
	// This ensures the chaining mechanism H∘(x) = H0(H1(x)), where the second hash function is applied to the result of the first.
	shake := sha3.NewShake256()                   // Create a SHAKE256 instance for further processing.
	shake.Write(chainHash1Result)                 // Apply SHAKE256 to the result of the first hash (chainHash1Result).
	shakeLength := s.Size()                       // Dynamically set the length of the output hash.
	chainHash2Result := make([]byte, shakeLength) // Dynamically allocate space for the result based on shakeLength.
	shake.Read(chainHash2Result)                  // Read the result into the allocated slice.

	// Step 3: Combine the two hashed results into one hash.
	// This concatenates (H|(x) = H0(x)|H1(x)) the results of the two hashes, which will be used for further processing.
	combinedHash := bytes.Join([][]byte{chainHash1Result[:], chainHash2Result[:]}, nil)

	// Step 3: Hash the combined result to generate a final chained hash.
	// By applying SHA-256 again on the combined hashes, we ensure that the final result has better security.
	chainHash := sha512.New512_256()
	chainHash.Write(combinedHash)         // Perform another SHA-512/256 hash on the combined result.
	chainHashResult := chainHash.Sum(nil) // Get the final hash.

	// Step 4: Initialize the output hash (sphinxHash) using the chained result.
	// The combined hash from the previous step becomes the starting point for further transformations.
	sphinxHash := chainHashResult // This is the current state of the hash.

	// Step 5: Apply iterative rounds to increase diffusion and avalanche effects.
	rounds := 2000 // Set the number of rounds for iterative hashing to enhance diffusion.
	// The number of rounds is a critical factor for making sure that the hash undergoes substantial transformations
	// through multiple rounds of mixing and re-hashing. The higher the number of rounds, the harder it becomes
	// to predict the final output, even with a quantum computer or brute force attack.

	for round := 0; round < rounds; round++ {
		// In each round, non-commutative operations like bit rotation and XOR are applied to ensure unpredictability and security.
		// These operations are designed to make the hash resistant to reverse engineering, ensuring that small changes in input data
		// lead to drastic changes in the resulting hash, making it computationally infeasible for an attacker to predict or reverse the output.

		// Loop through each byte in the current sphinxHash.
		for i := range sphinxHash {
			// Perform a left bit rotation by 3 positions to increase the diffusion of the hash.
			// This operation ensures that small changes in input data (even one bit) lead to significant changes in the output hash.
			// The goal of this operation is to ensure that every byte of the hash contributes to the final result, diffusing
			// the input values over the entire hash. This makes brute force attacks more difficult, as attackers cannot
			// predict how input data will affect the output after the transformations.
			sphinxHash[i] = (sphinxHash[i] << 3) | (sphinxHash[i] >> 5) // Bit rotation to the left by 3 bits.

			// XOR the rotated hash byte with a round-specific prime constant for non-commutative behavior.
			// The XOR operation is a key part of making the transformation non-commutative.
			// Non-commutative means that applying the same transformation in a different order results in a different output,
			// which increases security. By XORing the rotated value with a portion of a round-specific prime constant,
			// we ensure that each round introduces an additional layer of unpredictability.
			// This is particularly important for making the function more resistant to attacks such as Grover’s algorithm.
			// Since XORing is reversible without additional steps, having it combined with rotation and iterative rounds makes it
			// more difficult to undo and makes the attack surface larger.
			sphinxHash[i] ^= byte(primeConstant >> (round % 64)) // XOR with a shifting part of the prime constant.
		}

		// Re-hash the result after each round for additional diffusion and avalanche effects.
		// Re-hashing helps to spread the effects of the previous round across the entire hash.
		// It ensures that any small change in the input (even after multiple transformations) affects the final hash.
		// This step is crucial for increasing the diffusion, meaning that each output bit of the hash depends on many input bits.
		// This makes brute force attacks more difficult because attackers have to account for the cascade of changes caused by the previous rounds.
		// Grover's algorithm, which can provide a quadratic speedup for brute-forcing quantum-resistant functions, would be less effective here.
		// The multiple rounds of hashing make it harder to guess any specific bit of the output without fully processing through each round.
		chainHash.Write(sphinxHash)     // Re-hash the intermediate result.
		sphinxHash = chainHash.Sum(nil) // Update sphinxHash with the new hash value after each round.
	}

	// Step 6: Apply further mixing by adding the prime constant to each 64-bit segment of the hash.
	// This step ensures that the final result is heavily influenced by the prime constant to improve entropy and security.
	for i := 0; i < len(sphinxHash)/8; i++ {
		// Calculate the offset for each 8-byte (64-bit) segment.
		// Each iteration processes one 64-bit segment of the hash.
		offset := i * 8 // Multiply the loop index by 8 to get the starting index of the 64-bit segment.

		// Check if the current segment goes out of bounds (this ensures we are not reading past the end of the hash).
		// The 'offset+8' ensures that we are only reading 8 bytes, i.e., 64 bits at a time.
		if offset+8 <= len(sphinxHash) {
			// Read the current 64-bit segment of the hash in little-endian format.
			// We use the `binary.LittleEndian.Uint64` function to interpret the 8 bytes as a single 64-bit unsigned integer.
			// Little-endian means the least significant byte is stored first, which is a common format in many systems.
			val := binary.LittleEndian.Uint64(sphinxHash[offset : offset+8]) // Read 8 bytes and convert to uint64.

			// Add the prime constant to the current value to enhance entropy and security.
			// This step ensures that the prime constant influences the final hash, making it more unpredictable and harder to reverse-engineer.
			// By adding the prime constant to each segment of the hash, we effectively "mix" it into the hash at a more granular level.
			// This provides an additional layer of randomness and protects against potential weaknesses in the hash function.
			val += primeConstant // Add the prime constant to the 64-bit segment.

			// Write the updated value back to the original slice at the same offset.
			// We use `binary.LittleEndian.PutUint64` to write the updated 64-bit value back into the `sphinxHash` slice.
			// This operation ensures that the change is made in-place, modifying the original hash value.
			// Writing the result back to the same slice at the given offset ensures that the hash is updated with the new, mixed value.
			binary.LittleEndian.PutUint64(sphinxHash[offset:offset+8], val) // Store the updated value back into the hash.
		}
	}

	// Step 7: Return the final SphinxHash after all the hashing and mixing operations.
	// The final hash, after iterative rounds and mixing with the prime constant, is returned as the output.
	return sphinxHash // Output the final result after all transformations (already a []byte).
}
