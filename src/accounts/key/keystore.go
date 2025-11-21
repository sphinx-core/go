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

// go/src/account/key/keystore.go
package key

import (
	"fmt"
	"sync"
	"time"
)

// NewKeystoreConfig creates a new keystore configuration
func NewKeystoreConfig(chainID uint64, chainName string, bip44CoinType uint32, ledgerName string, symbol string) *KeystoreConfig {
	config := &KeystoreConfig{
		ChainID:         chainID,
		ChainName:       chainName,
		BIP44CoinType:   bip44CoinType,
		LedgerName:      ledgerName,
		Symbol:          symbol,
		DerivationPaths: make(map[HardwareWalletType]string),
	}

	// Initialize default derivation paths
	config.initializeDefaultPaths()

	return config
}

// initializeDefaultPaths sets up standard derivation paths for all wallet types
func (k *KeystoreConfig) initializeDefaultPaths() {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.DerivationPaths = map[HardwareWalletType]string{
		WalletTypeBIP44:  fmt.Sprintf("m/44'/%d'/0'/0/0", k.BIP44CoinType),
		WalletTypeBIP49:  fmt.Sprintf("m/49'/%d'/0'/0/0", k.BIP44CoinType),
		WalletTypeBIP84:  fmt.Sprintf("m/84'/%d'/0'/0/0", k.BIP44CoinType),
		WalletTypeLedger: fmt.Sprintf("m/44'/%d'/0'", k.BIP44CoinType),
		WalletTypeTrezor: fmt.Sprintf("m/44'/%d'/0'/0/0", k.BIP44CoinType),
		WalletTypeDisk:   fmt.Sprintf("m/44'/%d'/0'/0/0", k.BIP44CoinType), // Added Disk wallet derivation path
	}
}

// GetDerivationPath returns the derivation path for a specific wallet type
func (k *KeystoreConfig) GetDerivationPath(walletType HardwareWalletType) (string, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	path, exists := k.DerivationPaths[walletType]
	if !exists {
		return "", fmt.Errorf("unsupported wallet type: %s", walletType)
	}
	return path, nil
}

// SetCustomDerivationPath allows custom derivation paths for specific wallet types
func (k *KeystoreConfig) SetCustomDerivationPath(walletType HardwareWalletType, path string) {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.DerivationPaths[walletType] = path
}

// GetAllDerivationPaths returns all configured derivation paths
func (k *KeystoreConfig) GetAllDerivationPaths() map[HardwareWalletType]string {
	k.mu.RLock()
	defer k.mu.RUnlock()

	// Return a copy to prevent external modification
	paths := make(map[HardwareWalletType]string)
	for walletType, path := range k.DerivationPaths {
		paths[walletType] = path
	}
	return paths
}

// GetWalletDerivationPaths returns derivation paths in string map format for compatibility
func (k *KeystoreConfig) GetWalletDerivationPaths() map[string]string {
	k.mu.RLock()
	defer k.mu.RUnlock()

	paths := make(map[string]string)
	for walletType, path := range k.DerivationPaths {
		paths[string(walletType)] = path
	}
	return paths
}

// GenerateLedgerHeaders generates headers specifically formatted for Ledger hardware
func (k *KeystoreConfig) GenerateLedgerHeaders(operation string, amount float64, address string, memo string) string {
	bip44Path := k.DerivationPaths[WalletTypeBIP44]
	if bip44Path == "" {
		bip44Path = fmt.Sprintf("m/44'/%d'/0'/0/0", k.BIP44CoinType)
	}

	return fmt.Sprintf(
		"=== SPHINX LEDGER OPERATION ===\n"+
			"Chain: %s\n"+
			"Chain ID: %d\n"+
			"Operation: %s\n"+
			"Amount: %.6f %s\n"+
			"Address: %s\n"+
			"Memo: %s\n"+
			"BIP44: %s\n"+
			"Timestamp: %d\n"+
			"========================",
		k.ChainName,
		k.ChainID,
		operation,
		amount,
		k.Symbol,
		address,
		memo,
		bip44Path,
		time.Now().Unix(),
	)
}

// GenerateTrezorHeaders generates headers specifically formatted for Trezor hardware
func (k *KeystoreConfig) GenerateTrezorHeaders(operation string, amount float64, address string, memo string) string {
	trezorPath := k.DerivationPaths[WalletTypeTrezor]
	if trezorPath == "" {
		trezorPath = fmt.Sprintf("m/44'/%d'/0'/0/0", k.BIP44CoinType)
	}

	return fmt.Sprintf(
		"=== SPHINX TREZOR OPERATION ===\n"+
			"Chain: %s\n"+
			"Chain ID: %d\n"+
			"Operation: %s\n"+
			"Amount: %.6f %s\n"+
			"Address: %s\n"+
			"Memo: %s\n"+
			"Derivation: %s\n"+
			"Timestamp: %d\n"+
			"========================",
		k.ChainName,
		k.ChainID,
		operation,
		amount,
		k.Symbol,
		address,
		memo,
		trezorPath,
		time.Now().Unix(),
	)
}

// GenerateDiskHeaders generates headers specifically formatted for Disk wallet operations
func (k *KeystoreConfig) GenerateDiskHeaders(operation string, amount float64, address string, memo string) string {
	diskPath := k.DerivationPaths[WalletTypeDisk]
	if diskPath == "" {
		diskPath = fmt.Sprintf("m/44'/%d'/0'/0/0", k.BIP44CoinType)
	}

	return fmt.Sprintf(
		"=== SPHINX DISK OPERATION ===\n"+
			"Chain: %s\n"+
			"Chain ID: %d\n"+
			"Operation: %s\n"+
			"Amount: %.6f %s\n"+
			"Address: %s\n"+
			"Memo: %s\n"+
			"Derivation: %s\n"+
			"Timestamp: %d\n"+
			"Storage: disk\n"+
			"========================",
		k.ChainName,
		k.ChainID,
		operation,
		amount,
		k.Symbol,
		address,
		memo,
		diskPath,
		time.Now().Unix(),
	)
}

// ValidateDerivationPath validates if a derivation path follows expected format
func (k *KeystoreConfig) ValidateDerivationPath(path string, walletType HardwareWalletType) bool {
	expectedPath, err := k.GetDerivationPath(walletType)
	if err != nil {
		return false
	}
	return path == expectedPath
}

// Network-specific keystore configurations
func GetMainnetKeystoreConfig() *KeystoreConfig {
	return NewKeystoreConfig(7331, "Sphinx Mainnet", 7331, "Sphinx", "SPX")
}

func GetTestnetKeystoreConfig() *KeystoreConfig {
	return NewKeystoreConfig(17331, "Sphinx Testnet", 1, "Sphinx Testnet", "SPX")
}

func GetDevnetKeystoreConfig() *KeystoreConfig {
	return NewKeystoreConfig(7331, "Sphinx Devnet", 1, "Sphinx Devnet", "SPX")
}

// HardwareWalletManager manages multiple hardware wallet configurations
type HardwareWalletManager struct {
	mu      sync.RWMutex
	configs map[uint64]*KeystoreConfig // key: ChainID
}

func NewHardwareWalletManager() *HardwareWalletManager {
	mgr := &HardwareWalletManager{
		configs: make(map[uint64]*KeystoreConfig),
	}
	mgr.initializeNetworks()
	return mgr
}

func (m *HardwareWalletManager) initializeNetworks() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.configs[7331] = GetMainnetKeystoreConfig()
	m.configs[17331] = GetTestnetKeystoreConfig()
}

func (m *HardwareWalletManager) GetConfig(chainID uint64) (*KeystoreConfig, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	config, exists := m.configs[chainID]
	if !exists {
		return nil, fmt.Errorf("no keystore configuration found for chain ID: %d", chainID)
	}
	return config, nil
}

func (m *HardwareWalletManager) RegisterConfig(config *KeystoreConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.configs[config.ChainID] = config
}

// Global instance for easy access
var globalWalletManager *HardwareWalletManager
var once sync.Once

func GetWalletManager() *HardwareWalletManager {
	once.Do(func() {
		globalWalletManager = NewHardwareWalletManager()
	})
	return globalWalletManager
}
