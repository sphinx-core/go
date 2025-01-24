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
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,q
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package rpc

import (
	"sync"
	"time"
)

// Metrics struct holds all the metrics for monitoring.
type Metrics struct {
	mu           sync.Mutex
	requestCount int64
	errorCount   int64
	totalLatency time.Duration
}

var globalMetrics = &Metrics{}

// IncrementRequestCount increments the request counter.
func IncrementRequestCount() {
	globalMetrics.mu.Lock()
	defer globalMetrics.mu.Unlock()
	globalMetrics.requestCount++
}

// IncrementErrorCount increments the error counter.
func IncrementErrorCount() {
	globalMetrics.mu.Lock()
	defer globalMetrics.mu.Unlock()
	globalMetrics.errorCount++
}

// AddLatency adds the latency of a request to the total latency.
func AddLatency(latency time.Duration) {
	globalMetrics.mu.Lock()
	defer globalMetrics.mu.Unlock()
	globalMetrics.totalLatency += latency
}

// GetMetrics returns the current metrics.
func GetMetrics() (int64, int64, time.Duration) {
	globalMetrics.mu.Lock()
	defer globalMetrics.mu.Unlock()
	return globalMetrics.requestCount, globalMetrics.errorCount, globalMetrics.totalLatency
}
