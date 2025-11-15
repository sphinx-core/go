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

// go/src/core/config.go
package core

const (
	// StatusInitializing indicates the blockchain is starting up and loading blocks
	StatusInitializing BlockchainStatus = iota

	// StatusSyncing indicates the blockchain is synchronizing with the network
	StatusSyncing

	// StatusRunning indicates the blockchain is fully operational and processing blocks
	StatusRunning

	// StatusStopped indicates the blockchain has been stopped
	StatusStopped

	// StatusForked indicates the blockchain has detected a fork and needs resolution
	StatusForked
)

const (
	// SyncModeFull synchronizes the entire blockchain history
	SyncModeFull SyncMode = iota

	// SyncModeFast synchronizes only block headers and recent state
	SyncModeFast

	// SyncModeLight synchronizes only block headers for light clients
	SyncModeLight
)

const (
	// ImportedBest indicates the block was imported as the new best block
	ImportedBest BlockImportResult = iota

	// ImportedSide indicates the block was imported as a side chain block
	ImportedSide

	// ImportedExisting indicates the block was already known
	ImportedExisting

	// ImportInvalid indicates the block failed validation
	ImportInvalid

	// ImportedError indicates an error occurred during import
	ImportError
)

const (
	// CacheTypeBlock stores recently accessed blocks
	CacheTypeBlock CacheType = iota

	// CacheTypeTransaction stores recently accessed transactions
	CacheTypeTransaction

	// CacheTypeReceipt stores transaction receipts
	CacheTypeReceipt

	// CacheTypeState stores recent state objects
	CacheTypeState
)
