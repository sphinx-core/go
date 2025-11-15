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
	"encoding/json"
	"fmt"
	"os"
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

// WriteJSONToFile is kept for backward compatibility but only used for chain_identification.json
func WriteJSONToFile(data interface{}, filename string) error {
	outputDir := filepath.Join(DataDir, "output")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	filePath := filepath.Join(outputDir, filename)
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filePath, err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}

	return nil
}
