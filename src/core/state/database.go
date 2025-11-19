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

// go/src/core/state/database.go
package database

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	logger "github.com/sphinx-core/go/src/log"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

// NewLevelDB initializes a new LevelDB instance at the specified path with retry logic.
func NewLevelDB(path string) (*DB, error) {
	const maxRetries = 3
	const retryDelay = 1 * time.Second

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		logger.Error("Failed to create parent directory for LevelDB at %s: %v", path, err)
		return nil, fmt.Errorf("failed to create parent directory for LevelDB at %s: %w", path, err)
	}

	for attempt := 1; attempt <= maxRetries; attempt++ {
		if err := removeLockFile(path); err != nil {
			logger.Warn("Failed to remove lock file for LevelDB at %s on attempt %d: %v", path, attempt, err)
		}

		db, err := leveldb.OpenFile(path, &opt.Options{ErrorIfExist: false})
		if err == nil {
			logger.Info("Successfully opened LevelDB at %s on attempt %d", path, attempt)
			return &DB{
				db:    db,
				mutex: sync.RWMutex{},
			}, nil
		}

		logger.Error("Failed to open LevelDB at %s on attempt %d: %v", path, attempt, err)
		if attempt < maxRetries {
			logger.Info("Retrying LevelDB initialization at %s in %v", path, retryDelay)
			time.Sleep(retryDelay)
		}
	}

	logger.Warn("All attempts to open LevelDB at %s failed, attempting recovery", path)
	db, err := leveldb.RecoverFile(path, nil)
	if err != nil {
		logger.Error("Failed to recover LevelDB at %s: %v", path, err)
		return nil, fmt.Errorf("failed to recover LevelDB at %s: %w", path, err)
	}

	logger.Info("Successfully recovered LevelDB at %s", path)
	return &DB{
		db:    db,
		mutex: sync.RWMutex{},
	}, nil
}

// removeLockFile removes the LevelDB LOCK file if it exists.
func removeLockFile(path string) error {
	lockFile := filepath.Join(path, "LOCK")
	if _, err := os.Stat(lockFile); os.IsNotExist(err) {
		return nil
	}
	if err := os.Remove(lockFile); err != nil {
		return fmt.Errorf("failed to remove lock file at %s: %w", lockFile, err)
	}
	logger.Info("Removed stale lock file at %s", lockFile)
	return nil
}

// Close closes the LevelDB instance.
func (d *DB) Close() error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	if d.db == nil {
		return nil
	}
	if err := d.db.Close(); err != nil {
		logger.Error("Failed to close LevelDB: %v", err)
		return fmt.Errorf("failed to close LevelDB: %w", err)
	}
	d.db = nil
	logger.Info("Successfully closed LevelDB")
	return nil
}

// Put stores a key-value pair in the database.
func (d *DB) Put(key string, value []byte) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	if d.db == nil {
		return fmt.Errorf("LevelDB is closed")
	}
	if err := d.db.Put([]byte(key), value, nil); err != nil {
		logger.Error("Failed to put key %s in LevelDB: %s", key, err.Error())
		return fmt.Errorf("failed to put key %s in LevelDB: %w", key, err)
	}
	logger.Info("Successfully stored key %s in LevelDB", key)
	return nil
}

// Get retrieves a value by key from the database.
func (d *DB) Get(key string) ([]byte, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	if d.db == nil {
		return nil, fmt.Errorf("LevelDB is closed")
	}
	data, err := d.db.Get([]byte(key), nil)
	if err != nil {
		if err == errors.ErrNotFound {
			logger.Warn("Key %s not found in LevelDB", key)
			return nil, fmt.Errorf("key %s not found in LevelDB", key)
		}
		logger.Error("Failed to get key %s from LevelDB: %s", key, err.Error())
		return nil, fmt.Errorf("failed to get key %s from LevelDB: %w", key, err)
	}
	logger.Info("Successfully retrieved key %s from LevelDB", key)
	return data, nil
}

// Delete removes a key-value pair from the database.
func (d *DB) Delete(key string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	if d.db == nil {
		return fmt.Errorf("LevelDB is closed")
	}
	if err := d.db.Delete([]byte(key), nil); err != nil {
		logger.Error("Failed to delete key %s from LevelDB: %s", key, err.Error())
		return fmt.Errorf("failed to delete key %s from LevelDB: %w", key, err)
	}
	logger.Info("Successfully deleted key %s from LevelDB", key)
	return nil
}

// Has checks if a key exists in the database.
func (d *DB) Has(key string) (bool, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	if d.db == nil {
		return false, fmt.Errorf("LevelDB is closed")
	}
	_, err := d.db.Get([]byte(key), nil)
	if err != nil {
		if err == errors.ErrNotFound {
			return false, nil
		}
		logger.Error("Failed to check key %s in LevelDB: %s", key, err.Error())
		return false, fmt.Errorf("failed to check key %s in LevelDB: %w", key, err)
	}
	return true, nil
}
