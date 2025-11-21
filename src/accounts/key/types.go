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

// go/src/account/key/types.go
package key

import (
	"sync"
	"time"
)

// HardwareWalletType represents different wallet storage types
type HardwareWalletType string

const (
	WalletTypeLedger   HardwareWalletType = "Ledger"
	WalletTypeTrezor   HardwareWalletType = "Trezor"
	WalletTypeBIP44    HardwareWalletType = "BIP44"
	WalletTypeBIP49    HardwareWalletType = "BIP49"
	WalletTypeBIP84    HardwareWalletType = "BIP84"
	WalletTypeHot      HardwareWalletType = "HotWallet"
	WalletTypeCold     HardwareWalletType = "ColdWallet"
	WalletTypeSoftware HardwareWalletType = "Software"
	WalletTypeUSB      HardwareWalletType = "USB"
)

// KeyType represents the type of cryptographic key
type KeyType string

const (
	KeyTypeSPHINCSPlus KeyType = "sphincs+"
)

// StorageLocation represents where the key is stored
type StorageLocation string

const (
	StorageLocal  StorageLocation = "local"
	StorageUSB    StorageLocation = "usb"
	StorageRemote StorageLocation = "remote"
)

// KeyPair represents a stored key pair
type KeyPair struct {
	ID             string                 `json:"id"`
	EncryptedSK    []byte                 `json:"encrypted_sk"` // Encrypted secret key
	PublicKey      []byte                 `json:"public_key"`
	Address        string                 `json:"address"`
	KeyType        KeyType                `json:"key_type"`
	WalletType     HardwareWalletType     `json:"wallet_type"`
	DerivationPath string                 `json:"derivation_path,omitempty"`
	ChainID        uint64                 `json:"chain_id"`
	CreatedAt      time.Time              `json:"created_at"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// WalletInfo contains wallet metadata
type WalletInfo struct {
	ID           string             `json:"id"`
	Name         string             `json:"name"`
	WalletType   HardwareWalletType `json:"wallet_type"`
	Storage      StorageLocation    `json:"storage"`
	CreatedAt    time.Time          `json:"created_at"`
	LastAccessed time.Time          `json:"last_accessed"`
	KeyCount     int                `json:"key_count"`
}

// KeystoreConfig holds configuration for hardware wallet integration
type KeystoreConfig struct {
	mu sync.RWMutex

	// Chain-specific parameters
	ChainID       uint64
	ChainName     string
	BIP44CoinType uint32
	LedgerName    string

	// Wallet-specific derivation paths
	DerivationPaths map[HardwareWalletType]string

	// Network identification
	MagicNumber uint32
	Symbol      string
}
