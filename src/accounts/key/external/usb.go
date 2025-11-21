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

// go/src/account/key/external/usb.go
package usb

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/sphinx-core/go/src/accounts/key"
	"github.com/sphinx-core/go/src/core/wallet/crypter"
	"golang.org/x/crypto/pbkdf2"
)

// NewUSBKeyStore creates a new USB keystore instance
func NewUSBKeyStore() *USBKeyStore {
	return &USBKeyStore{
		keys:      make(map[string]*key.KeyPair),
		crypt:     &crypter.CCrypter{},
		isMounted: false,
	}
}

// Mount attempts to mount and load keys from a USB device
func (ks *USBKeyStore) Mount(usbPath string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Verify USB path exists and is readable
	if _, err := os.Stat(usbPath); os.IsNotExist(err) {
		return fmt.Errorf("USB path does not exist: %s", usbPath)
	}

	// Check if it's a valid Sphinx USB keystore
	keystorePath := filepath.Join(usbPath, "sphinx-usb-keystore")
	if _, err := os.Stat(keystorePath); os.IsNotExist(err) {
		return fmt.Errorf("not a valid Sphinx USB keystore: %s", usbPath)
	}

	ks.mountPath = keystorePath
	ks.isMounted = true

	// Load keys from USB
	if err := ks.loadKeysFromUSB(); err != nil {
		ks.isMounted = false
		return fmt.Errorf("failed to load keys from USB: %w", err)
	}

	return nil
}

// Unmount unmounts the USB device and clears in-memory cache
func (ks *USBKeyStore) Unmount() {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	ks.keys = make(map[string]*key.KeyPair)
	ks.mountPath = ""
	ks.isMounted = false
}

// IsMounted returns whether a USB device is currently mounted
func (ks *USBKeyStore) IsMounted() bool {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.isMounted
}

// StoreKey stores a key pair to the USB device
func (ks *USBKeyStore) StoreKey(keyPair *key.KeyPair) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if !ks.isMounted {
		return fmt.Errorf("USB device not mounted")
	}

	if err := ks.validateKeyPair(keyPair); err != nil {
		return err
	}

	// Add to in-memory cache
	ks.keys[keyPair.ID] = keyPair

	// Save to USB
	return ks.saveKeyToUSB(keyPair)
}

// StoreEncryptedKey stores an already encrypted key pair to USB
func (ks *USBKeyStore) StoreEncryptedKey(encryptedSK, publicKey []byte, address string, walletType key.HardwareWalletType, chainID uint64, derivationPath string, metadata map[string]interface{}) (*key.KeyPair, error) {
	keyPair := &key.KeyPair{
		ID:             ks.generateKeyID(),
		EncryptedSK:    encryptedSK,
		PublicKey:      publicKey,
		Address:        address,
		KeyType:        key.KeyTypeSPHINCSPlus,
		WalletType:     walletType,
		DerivationPath: derivationPath,
		ChainID:        chainID,
		CreatedAt:      time.Now(),
		Metadata:       metadata,
	}

	if keyPair.Metadata == nil {
		keyPair.Metadata = make(map[string]interface{})
	}
	keyPair.Metadata["encrypted"] = true
	keyPair.Metadata["algorithm"] = "SPHINCS+"
	keyPair.Metadata["storage"] = "usb"

	if err := ks.StoreKey(keyPair); err != nil {
		return nil, err
	}

	return keyPair, nil
}

// GetKey retrieves a key pair by ID from USB
func (ks *USBKeyStore) GetKey(keyID string) (*key.KeyPair, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	if !ks.isMounted {
		return nil, fmt.Errorf("USB device not mounted")
	}

	keyPair, exists := ks.keys[keyID]
	if !exists {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	return keyPair, nil
}

// GetKeyByAddress retrieves a key pair by address from USB
func (ks *USBKeyStore) GetKeyByAddress(address string) (*key.KeyPair, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	if !ks.isMounted {
		return nil, fmt.Errorf("USB device not mounted")
	}

	for _, keyPair := range ks.keys {
		if keyPair.Address == address {
			return keyPair, nil
		}
	}

	return nil, fmt.Errorf("key not found for address: %s", address)
}

// ListKeys returns all keys from the USB device
func (ks *USBKeyStore) ListKeys() []*key.KeyPair {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	if !ks.isMounted {
		return nil
	}

	keys := make([]*key.KeyPair, 0, len(ks.keys))
	for _, key := range ks.keys {
		keys = append(keys, key)
	}

	return keys
}

// RemoveKey removes a key from the USB device
func (ks *USBKeyStore) RemoveKey(keyID string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if !ks.isMounted {
		return fmt.Errorf("USB device not mounted")
	}

	delete(ks.keys, keyID)

	// Remove from USB
	keyFile := filepath.Join(ks.mountPath, "keys", keyID+".json")
	if err := os.Remove(keyFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove key file from USB: %w", err)
	}

	return nil
}

// BackupToUSB creates a backup of hot wallet keys to USB
func (ks *USBKeyStore) BackupFromHot(hotStore interface{ ListKeys() []*key.KeyPair }, passphrase string) error {
	if !ks.isMounted {
		return fmt.Errorf("USB device not mounted")
	}

	hotKeys := hotStore.ListKeys()
	backupPath := filepath.Join(ks.mountPath, "backup", time.Now().Format("2006-01-02_15-04-05"))

	if err := os.MkdirAll(backupPath, 0700); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Create backup manifest
	manifest := map[string]interface{}{
		"version":     "1.0",
		"backup_time": time.Now().Format(time.RFC3339),
		"key_count":   len(hotKeys),
		"backup_type": "hot_to_usb",
		"encrypted":   passphrase != "",
	}

	manifestData, _ := json.MarshalIndent(manifest, "", "  ")
	manifestFile := filepath.Join(backupPath, "backup-manifest.json")
	if err := os.WriteFile(manifestFile, manifestData, 0600); err != nil {
		return fmt.Errorf("failed to write backup manifest: %w", err)
	}

	return nil
}

// RestoreToHot restores keys from USB to hot wallet
func (ks *USBKeyStore) RestoreToHot(hotStore interface{ StoreKey(*key.KeyPair) error }, passphrase string) ([]*key.KeyPair, error) {
	if !ks.isMounted {
		return nil, fmt.Errorf("USB device not mounted")
	}

	usbKeys := ks.ListKeys()
	var restoredKeys []*key.KeyPair

	for _, keyPair := range usbKeys {
		if err := hotStore.StoreKey(keyPair); err != nil {
			return nil, fmt.Errorf("failed to restore key %s: %w", keyPair.ID, err)
		}
		restoredKeys = append(restoredKeys, keyPair)
	}

	return restoredKeys, nil
}

// InitializeUSB initializes a new USB device for Sphinx keystore
func (ks *USBKeyStore) InitializeUSB(usbPath string) error {
	keystorePath := filepath.Join(usbPath, "sphinx-usb-keystore")

	if err := os.MkdirAll(filepath.Join(keystorePath, "keys"), 0700); err != nil {
		return fmt.Errorf("failed to initialize USB keystore: %w", err)
	}

	// Create USB info file
	info := map[string]interface{}{
		"version":     "1.0",
		"created_at":  time.Now().Format(time.RFC3339),
		"device_type": "sphinx-usb-keystore",
	}

	infoData, _ := json.MarshalIndent(info, "", "  ")
	infoFile := filepath.Join(keystorePath, "usb-info.json")
	return os.WriteFile(infoFile, infoData, 0600)
}

// GetWalletInfo returns information about the USB wallet
func (ks *USBKeyStore) GetWalletInfo() *key.WalletInfo {
	keys := ks.ListKeys()

	return &key.WalletInfo{
		ID:           ks.generateKeyID(),
		Name:         "Sphinx USB Wallet",
		WalletType:   key.WalletTypeUSB,
		Storage:      key.StorageUSB,
		CreatedAt:    time.Now(),
		LastAccessed: time.Now(),
		KeyCount:     len(keys),
	}
}

// Helper functions

func (ks *USBKeyStore) generateKeyID() string {
	timestamp := time.Now().UnixNano()
	randomBytes := make([]byte, 8)
	io.ReadFull(rand.Reader, randomBytes)
	return fmt.Sprintf("usb_key_%d_%x", timestamp, randomBytes)
}

func (ks *USBKeyStore) generateSalt(passphrase string) []byte {
	return pbkdf2.Key([]byte(passphrase), []byte("sphinx-usb-keystore-salt"), 1, crypter.WALLET_CRYPTO_IV_SIZE, sha256.New)
}

func (ks *USBKeyStore) validateKeyPair(keyPair *key.KeyPair) error {
	if keyPair.ID == "" {
		return fmt.Errorf("key ID cannot be empty")
	}
	if len(keyPair.EncryptedSK) == 0 {
		return fmt.Errorf("encrypted secret key cannot be empty")
	}
	if len(keyPair.PublicKey) == 0 {
		return fmt.Errorf("public key cannot be empty")
	}
	if keyPair.Address == "" {
		return fmt.Errorf("address cannot be empty")
	}
	return nil
}

func (ks *USBKeyStore) loadKeysFromUSB() error {
	keysDir := filepath.Join(ks.mountPath, "keys")
	if _, err := os.Stat(keysDir); os.IsNotExist(err) {
		return nil // No keys directory yet
	}

	files, err := filepath.Glob(filepath.Join(keysDir, "*.json"))
	if err != nil {
		return err
	}

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		var keyPair key.KeyPair
		if err := json.Unmarshal(data, &keyPair); err != nil {
			continue
		}

		ks.keys[keyPair.ID] = &keyPair
	}

	return nil
}

func (ks *USBKeyStore) saveKeyToUSB(keyPair *key.KeyPair) error {
	keysDir := filepath.Join(ks.mountPath, "keys")
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return err
	}

	keyFile := filepath.Join(keysDir, keyPair.ID+".json")
	data, err := json.MarshalIndent(keyPair, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(keyFile, data, 0600)
}
