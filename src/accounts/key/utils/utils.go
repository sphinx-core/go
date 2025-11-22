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

// go/src/account/key/utils/utils.go
package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/sphinx-core/go/src/accounts/key"
	disk "github.com/sphinx-core/go/src/accounts/key/disk"
	usb "github.com/sphinx-core/go/src/accounts/key/external"
)

// NewStorageManager creates a new storage manager
func NewStorageManager() (*StorageManager, error) {
	diskStore, err := disk.NewDiskKeyStore("")
	if err != nil {
		return nil, fmt.Errorf("failed to create disk storage: %w", err)
	}

	return &StorageManager{
		diskStore: diskStore,
		usbStore:  usb.NewUSBKeyStore(),
	}, nil
}

// GetStorage returns the appropriate storage based on type - FIXED SIGNATURE
func (sm *StorageManager) GetStorage(storageType string) key.StorageInterface {
	switch StorageType(storageType) {
	case StorageTypeDisk:
		return sm.diskStore
	case StorageTypeUSB:
		return sm.usbStore
	default:
		return sm.diskStore
	}
}

// MountUSB mounts a USB device for storage
func (sm *StorageManager) MountUSB(usbPath string) error {
	return sm.usbStore.Mount(usbPath)
}

// UnmountUSB unmounts the USB device
func (sm *StorageManager) UnmountUSB() {
	sm.usbStore.Unmount()
}

// IsUSBMounted checks if a USB device is mounted
func (sm *StorageManager) IsUSBMounted() bool {
	return sm.usbStore.IsMounted()
}

// InitializeUSBStorage initializes a new USB device for Sphinx
func (sm *StorageManager) InitializeUSBStorage(usbPath string) error {
	return sm.usbStore.InitializeUSB(usbPath)
}

// BackupToUSB creates a backup of disk wallet to USB
func (sm *StorageManager) BackupToUSB(passphrase string) error {
	if !sm.IsUSBMounted() {
		return fmt.Errorf("USB device not mounted")
	}
	return sm.usbStore.BackupFromDisk(sm.diskStore, passphrase)
}

// RestoreFromUSB restores keys from USB to disk wallet
func (sm *StorageManager) RestoreFromUSB(passphrase string) (int, error) {
	if !sm.IsUSBMounted() {
		return 0, fmt.Errorf("USB device not mounted")
	}
	keys, err := sm.usbStore.RestoreToDisk(sm.diskStore, passphrase)
	if err != nil {
		return 0, err
	}
	return len(keys), nil
}

// GetStorageInfo returns information about all storage types - FIXED SIGNATURE
func (sm *StorageManager) GetStorageInfo() map[string]interface{} {
	info := make(map[string]interface{})

	// Disk storage info
	diskInfo := sm.diskStore.GetWalletInfo()
	info["disk"] = map[string]interface{}{
		"type":          "disk",
		"key_count":     diskInfo.KeyCount,
		"last_accessed": diskInfo.LastAccessed,
		"storage_path":  getDefaultDiskStoragePath(),
	}

	// USB storage info
	usbInfo := sm.usbStore.GetWalletInfo()
	info["usb"] = map[string]interface{}{
		"type":          "usb",
		"key_count":     usbInfo.KeyCount,
		"last_accessed": usbInfo.LastAccessed,
		"is_mounted":    sm.IsUSBMounted(),
	}

	return info
}

// CreateDefaultDirectories creates all necessary directories for Sphinx keystore
func CreateDefaultDirectories() error {
	// Create disk storage directory
	diskPath := getDefaultDiskStoragePath()
	if err := os.MkdirAll(filepath.Join(diskPath, "keys"), 0700); err != nil {
		return fmt.Errorf("failed to create disk storage directory: %w", err)
	}

	// Create backup directory
	backupPath := getDefaultBackupPath()
	if err := os.MkdirAll(backupPath, 0700); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Create config directory
	configPath := getDefaultConfigPath()
	if err := os.MkdirAll(configPath, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	return nil
}

// GetRecommendedStorage returns the recommended storage type based on system
func GetRecommendedStorage() StorageType {
	if isProductionEnvironment() {
		return StorageTypeUSB
	}
	return StorageTypeDisk
}

// Helper functions

func getDefaultDiskStoragePath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "./sphinx-disk-keystore"
	}
	return filepath.Join(homeDir, ".sphinx", "disk-keystore")
}

func getDefaultBackupPath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "./sphinx-backups"
	}
	return filepath.Join(homeDir, ".sphinx", "backups")
}

func getDefaultConfigPath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "./sphinx-config"
	}
	return filepath.Join(homeDir, ".sphinx", "config")
}

func isProductionEnvironment() bool {
	return runtime.GOOS != "darwin"
}

// ValidateStoragePath validates if a path is suitable for storage
func ValidateStoragePath(path string, storageType StorageType) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("path does not exist: %s", path)
	}

	testFile := filepath.Join(path, ".write-test")
	if err := os.WriteFile(testFile, []byte("test"), 0600); err != nil {
		return fmt.Errorf("path is not writable: %s", path)
	}
	os.Remove(testFile)

	if storageType == StorageTypeUSB {
		if filepath.VolumeName(path) == "" {
			return fmt.Errorf("path does not appear to be a removable drive: %s", path)
		}
	}

	return nil
}
