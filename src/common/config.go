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
	"strings"
)

const (
	// TestDataDir is the unified test data directory
	DataDir = "data"
)

// WriteJSONToFile writes data to JSON file in output directory
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

// Remove simple node name mappings and use only network addresses
func GetNodeIdentifier(address string) string {
	return fmt.Sprintf("Node-%s", address)
}

// Extract port from address for identification
func GetNodePortFromAddress(address string) string {
	parts := strings.Split(address, ":")
	if len(parts) == 2 {
		return parts[1]
	}
	return address
}

// GetNodeDataDir now only uses network address format
func GetNodeDataDir(address string) string {
	nodeIdentifier := GetNodeIdentifier(address)
	return filepath.Join(DataDir, nodeIdentifier)
}

// Update all path functions to use address directly
func GetLevelDBPath(address string) string {
	return filepath.Join(GetNodeDataDir(address), "leveldb")
}

func GetBlockchainDataDir(address string) string {
	return filepath.Join(GetNodeDataDir(address), "blockchain")
}

func GetKeysDataDir(address string) string {
	return filepath.Join(GetNodeDataDir(address), "keys")
}

func GetPrivateKeyPath(address string) string {
	return filepath.Join(GetKeysDataDir(address), "private.key")
}

func GetPublicKeyPath(address string) string {
	return filepath.Join(GetKeysDataDir(address), "public.key")
}

func GetNodeInfoPath(address string) string {
	return filepath.Join(GetKeysDataDir(address), "node_info.json")
}

// EnsureNodeDirs creates directories using network address format
func EnsureNodeDirs(address string) error {
	dirs := []string{
		GetNodeDataDir(address),
		GetLevelDBPath(address),
		GetBlockchainDataDir(address),
		GetKeysDataDir(address),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}
	return nil
}

// WriteKeysToFile writes keys using network address
func WriteKeysToFile(address string, privateKey, publicKey []byte) error {
	if err := EnsureNodeDirs(address); err != nil {
		return err
	}

	privateKeyPath := GetPrivateKeyPath(address)
	if err := os.WriteFile(privateKeyPath, privateKey, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	publicKeyPath := GetPublicKeyPath(address)
	if err := os.WriteFile(publicKeyPath, publicKey, 0644); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	return nil
}

// ReadKeysFromFile reads keys using network address
func ReadKeysFromFile(address string) ([]byte, []byte, error) {
	privateKeyPath := GetPrivateKeyPath(address)
	publicKeyPath := GetPublicKeyPath(address)

	privateKey, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read private key: %w", err)
	}

	publicKey, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read public key: %w", err)
	}

	return privateKey, publicKey, nil
}

// KeysExist checks if keys exist for a network address
func KeysExist(address string) bool {
	privateKeyPath := GetPrivateKeyPath(address)
	publicKeyPath := GetPublicKeyPath(address)

	_, privateErr := os.Stat(privateKeyPath)
	_, publicErr := os.Stat(publicKeyPath)

	return privateErr == nil && publicErr == nil
}

// WriteNodeInfo writes node information using network address
func WriteNodeInfo(address string, nodeInfo map[string]interface{}) error {
	if err := EnsureNodeDirs(address); err != nil {
		return err
	}

	nodeInfoPath := GetNodeInfoPath(address)
	file, err := os.Create(nodeInfoPath)
	if err != nil {
		return fmt.Errorf("failed to create node info file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(nodeInfo); err != nil {
		return fmt.Errorf("failed to encode node info: %w", err)
	}

	return nil
}

// ReadNodeInfo reads node information using network address
func ReadNodeInfo(address string) (map[string]interface{}, error) {
	nodeInfoPath := GetNodeInfoPath(address)
	data, err := os.ReadFile(nodeInfoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read node info: %w", err)
	}

	var nodeInfo map[string]interface{}
	if err := json.Unmarshal(data, &nodeInfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal node info: %w", err)
	}

	return nodeInfo, nil
}
