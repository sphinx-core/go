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

// go/src/core/transaction/bench.go
package types

import (
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	logger "github.com/sphinx-core/go/src/log"
)

// TPSMonitor tracks transactions per second metrics
type TPSMonitor struct {
	mu sync.RWMutex

	// Transaction counters
	totalTransactions  uint64
	currentWindowCount uint64
	windowStartTime    time.Time

	// TPS metrics
	currentTPS     float64
	averageTPS     float64
	peakTPS        float64
	windowDuration time.Duration

	// Historical data
	tpsHistory     []float64
	maxHistorySize int

	// Block-based metrics
	blocksProcessed uint64
	txsPerBlock     []uint64
}

// NewTPSMonitor creates a new TPS monitor
func NewTPSMonitor(windowDuration time.Duration) *TPSMonitor {
	return &TPSMonitor{
		windowStartTime: time.Now(),
		windowDuration:  windowDuration,
		tpsHistory:      make([]float64, 0),
		maxHistorySize:  1000, // Keep last 1000 measurements
		txsPerBlock:     make([]uint64, 0),
	}
}

// RecordTransaction records a new transaction for TPS calculation
func (tm *TPSMonitor) RecordTransaction() {
	atomic.AddUint64(&tm.totalTransactions, 1)
	atomic.AddUint64(&tm.currentWindowCount, 1)
	tm.updateTPS()
}

// RecordBlock records block information for block-based TPS calculation
func (tm *TPSMonitor) RecordBlock(txCount uint64, blockTime time.Duration) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	atomic.AddUint64(&tm.blocksProcessed, 1)
	tm.txsPerBlock = append(tm.txsPerBlock, txCount)

	// Calculate block TPS
	if blockTime > 0 {
		blockTPS := float64(txCount) / blockTime.Seconds()
		tm.updateHistory(blockTPS)
	}

	// Keep only recent history
	if len(tm.txsPerBlock) > tm.maxHistorySize {
		tm.txsPerBlock = tm.txsPerBlock[1:]
	}
}

// updateTPS calculates current TPS
func (tm *TPSMonitor) updateTPS() {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	now := time.Now()
	windowElapsed := now.Sub(tm.windowStartTime)

	if windowElapsed >= tm.windowDuration {
		// Calculate TPS for completed window
		windowTPS := float64(atomic.LoadUint64(&tm.currentWindowCount)) / windowElapsed.Seconds()

		tm.currentTPS = windowTPS
		tm.updateHistory(windowTPS)

		// Update peak TPS
		if windowTPS > tm.peakTPS {
			tm.peakTPS = windowTPS
		}

		// Reset window
		atomic.StoreUint64(&tm.currentWindowCount, 0)
		tm.windowStartTime = now

		logger.Debug("TPS update: current=%.2f, peak=%.2f, total_txs=%d",
			tm.currentTPS, tm.peakTPS, atomic.LoadUint64(&tm.totalTransactions))
	}
}

// updateHistory updates TPS history
func (tm *TPSMonitor) updateHistory(tps float64) {
	tm.tpsHistory = append(tm.tpsHistory, tps)

	// Calculate rolling average
	var sum float64
	for _, val := range tm.tpsHistory {
		sum += val
	}
	tm.averageTPS = sum / float64(len(tm.tpsHistory))

	// Maintain history size
	if len(tm.tpsHistory) > tm.maxHistorySize {
		tm.tpsHistory = tm.tpsHistory[1:]
	}
}

// GetStats returns current TPS statistics
func (tm *TPSMonitor) GetStats() map[string]interface{} {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	return map[string]interface{}{
		"current_tps":          tm.currentTPS,
		"average_tps":          tm.averageTPS,
		"peak_tps":             tm.peakTPS,
		"total_transactions":   atomic.LoadUint64(&tm.totalTransactions),
		"blocks_processed":     atomic.LoadUint64(&tm.blocksProcessed),
		"current_window_count": atomic.LoadUint64(&tm.currentWindowCount),
		"window_duration_sec":  tm.windowDuration.Seconds(),
		"history_size":         len(tm.tpsHistory),
		"avg_txs_per_block":    tm.calculateAverageTxsPerBlock(),
	}
}

// GetDetailedStats returns comprehensive TPS statistics
func (tm *TPSMonitor) GetDetailedStats() map[string]interface{} {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	stats := tm.GetStats()

	// Add percentile data
	stats["txs_per_block_stats"] = tm.calculateTxsPerBlockStats()
	stats["tps_history_recent"] = tm.getRecentTPSHistory(10) // Last 10 measurements
	stats["current_window_start"] = tm.windowStartTime.Format(time.RFC3339)

	return stats
}

// calculateAverageTxsPerBlock calculates average transactions per block
func (tm *TPSMonitor) calculateAverageTxsPerBlock() float64 {
	if len(tm.txsPerBlock) == 0 {
		return 0
	}

	var sum uint64
	for _, count := range tm.txsPerBlock {
		sum += count
	}
	return float64(sum) / float64(len(tm.txsPerBlock))
}

// calculateTxsPerBlockStats calculates statistics for transactions per block
func (tm *TPSMonitor) calculateTxsPerBlockStats() map[string]interface{} {
	if len(tm.txsPerBlock) == 0 {
		return map[string]interface{}{
			"min":   0,
			"max":   0,
			"mean":  0,
			"count": 0,
		}
	}

	var min, max, sum uint64
	min = ^uint64(0) // Max uint64

	for _, count := range tm.txsPerBlock {
		if count < min {
			min = count
		}
		if count > max {
			max = count
		}
		sum += count
	}

	return map[string]interface{}{
		"min":   min,
		"max":   max,
		"mean":  float64(sum) / float64(len(tm.txsPerBlock)),
		"count": len(tm.txsPerBlock),
	}
}

// getRecentTPSHistory returns recent TPS history
func (tm *TPSMonitor) getRecentTPSHistory(count int) []float64 {
	if len(tm.tpsHistory) == 0 {
		return []float64{}
	}

	start := len(tm.tpsHistory) - count
	if start < 0 {
		start = 0
	}

	return tm.tpsHistory[start:]
}

// Reset resets the TPS monitor (useful for tests)
func (tm *TPSMonitor) Reset() {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	atomic.StoreUint64(&tm.totalTransactions, 0)
	atomic.StoreUint64(&tm.currentWindowCount, 0)
	atomic.StoreUint64(&tm.blocksProcessed, 0)

	tm.currentTPS = 0
	tm.averageTPS = 0
	tm.peakTPS = 0
	tm.windowStartTime = time.Now()
	tm.tpsHistory = make([]float64, 0)
	tm.txsPerBlock = make([]uint64, 0)
}

// Benchmarking to ensure the Merkle tree implementation is efficient
func BenchmarkMerkleTree(b *testing.B) {
	// Create many transactions for benchmarking
	var txs []*Transaction
	for i := 0; i < 1000; i++ {
		txs = append(txs, &Transaction{
			ID:       fmt.Sprintf("tx%d", i),
			Sender:   "alice",
			Receiver: "bob",
			Amount:   big.NewInt(int64(i)),
			GasLimit: big.NewInt(21000),
			GasPrice: big.NewInt(10),
			Nonce:    uint64(i),
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewMerkleTree(txs)
	}
}

// BenchmarkTransactionProcessing benchmarks transaction processing
func BenchmarkTransactionProcessing(b *testing.B) {
	monitor := NewTPSMonitor(time.Second)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tx := &Transaction{
			ID:       fmt.Sprintf("benchmark-tx-%d", i),
			Sender:   "benchmark-sender",
			Receiver: "benchmark-receiver",
			Amount:   big.NewInt(int64(i % 1000)),
			GasLimit: big.NewInt(21000),
			GasPrice: big.NewInt(10),
			Nonce:    uint64(i),
		}

		// Simulate transaction processing
		monitor.RecordTransaction()

		// Validate transaction (simulated)
		_ = tx.SanityCheck()
	}
}

// BenchmarkTPSMonitoring benchmarks TPS monitoring itself
func BenchmarkTPSMonitoring(b *testing.B) {
	monitor := NewTPSMonitor(time.Second)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		monitor.RecordTransaction()
		if i%1000 == 0 {
			_ = monitor.GetStats()
		}
	}
}

// BenchmarkRealWorldTPS simulates real-world TPS patterns
func BenchmarkRealWorldTPS(b *testing.B) {
	monitor := NewTPSMonitor(time.Second)

	// Simulate bursty traffic pattern
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Simulate transaction bursts
		if i%100 == 0 {
			// Burst of 10 transactions
			for j := 0; j < 10; j++ {
				monitor.RecordTransaction()
			}
		} else {
			monitor.RecordTransaction()
		}

		// Simulate block creation every 1000 transactions
		if i%1000 == 0 && i > 0 {
			monitor.RecordBlock(50, 5*time.Second) // 50 txs in 5 seconds
		}
	}

	stats := monitor.GetStats()
	b.ReportMetric(stats["average_tps"].(float64), "avg_tps")
	b.ReportMetric(stats["peak_tps"].(float64), "peak_tps")
}
