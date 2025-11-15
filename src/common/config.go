// MIT License
//
// # Copyright (c) 2024 sphinx-core
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

// go/src/common/config.go
package common

import (
	"path/filepath"
)

const (
	// TestDataDir is the unified test data directory
	DataDir = "data"
)

// GetNodeDataDir returns the standardized data directory for a node
func GetNodeDataDir(nodeName string) string {
	return filepath.Join(DataDir, nodeName)
}

// GetLevelDBPath returns the standardized LevelDB path for a node
func GetLevelDBPath(nodeName string) string {
	return filepath.Join(GetNodeDataDir(nodeName), "leveldb")
}

// GetBlockchainDataDir returns the standardized blockchain data directory
func GetBlockchainDataDir(nodeName string) string {
	return filepath.Join(GetNodeDataDir(nodeName), "blockchain")
}
