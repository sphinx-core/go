package util

import (
	disk "github.com/sphinx-core/go/src/accounts/key/disk"
	usb "github.com/sphinx-core/go/src/accounts/key/external"
)

// StorageType represents the type of storage
type StorageType string

// StorageManager manages multiple storage types
type StorageManager struct {
	hotStore *disk.HotKeyStore
	usbStore *usb.USBKeyStore
}
