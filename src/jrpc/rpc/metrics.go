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

// Metrics struct holds all the metrics for monitoring the RPC system's performance.
// It includes counters for requests, errors, successful requests, total latency, and a histogram of latency.
type Metrics struct {
	mu               sync.Mutex       // Mutex to protect concurrent access to the metrics. This prevents data races.
	requestCount     int64            // Counter for the total number of requests received and processed by the RPC system.
	errorCount       int64            // Counter for the total number of errors encountered during RPC processing.
	successCount     int64            // Counter for the total number of successful RPC requests.
	totalLatency     time.Duration    // Total latency accumulated over all processed requests. This is used to track system performance.
	latencyHistogram map[string]int64 // A histogram that categorizes latency into defined buckets like "0-50ms", "50-100ms", etc.
}

// globalMetrics holds the global instance of the Metrics struct.
// This single instance is used to track and monitor metrics across all requests and errors in the RPC system.
var globalMetrics = &Metrics{
	latencyHistogram: make(map[string]int64), // Initializing the latency histogram as an empty map.
}

// IncrementRequestCount increments the request counter.
// This method is called whenever a new request is processed.
func IncrementRequestCount() {
	globalMetrics.mu.Lock()         // Locking the mutex to safely modify the requestCount counter.
	defer globalMetrics.mu.Unlock() // Ensure the mutex is unlocked once the function exits, even if there's an error.
	globalMetrics.requestCount++    // Incrementing the request count by 1.
}

// IncrementErrorCount increments the error counter.
// This method is called when an error occurs during the processing of a request.
func IncrementErrorCount() {
	globalMetrics.mu.Lock()         // Locking the mutex to safely modify the errorCount counter.
	defer globalMetrics.mu.Unlock() // Unlock the mutex when done to avoid blocking other parts of the code.
	globalMetrics.errorCount++      // Incrementing the error count by 1.
}

// IncrementSuccessCount increments the success counter.
// This method is called when a request is successfully processed without any errors.
func IncrementSuccessCount() {
	globalMetrics.mu.Lock()         // Locking the mutex to safely modify the successCount counter.
	defer globalMetrics.mu.Unlock() // Unlock the mutex when the function finishes.
	globalMetrics.successCount++    // Incrementing the success count by 1.
}

// AddLatency adds the latency of a request to the total latency and updates the latency histogram.
// Latency is a measure of how long it takes to process a request and is added to the total system latency.
func AddLatency(latency time.Duration) {
	// Define latency buckets for categorizing the latency into predefined ranges.
	var bucket string
	switch {
	case latency <= 50*time.Millisecond:
		bucket = "0-50ms" // If latency is 50ms or less, it goes into the "0-50ms" bucket.
	case latency <= 100*time.Millisecond:
		bucket = "50-100ms" // If latency is between 50ms and 100ms, it goes into the "50-100ms" bucket.
	case latency <= 200*time.Millisecond:
		bucket = "100-200ms" // If latency is between 100ms and 200ms, it goes into the "100-200ms" bucket.
	default:
		bucket = "200ms+" // For latencies greater than 200ms, they fall into the "200ms+" bucket.
	}

	// Locking the mutex to safely modify metrics in a concurrent environment.
	globalMetrics.mu.Lock()
	defer globalMetrics.mu.Unlock()

	// Update the total latency by adding the latency of the current request.
	globalMetrics.totalLatency += latency
	// Increment the count for the corresponding latency bucket in the histogram.
	globalMetrics.latencyHistogram[bucket]++
}

// GetMetrics returns the current metrics, including:
// 1. Total request count
// 2. Total error count
// 3. Total success count
// 4. Total latency accumulated across all requests
// 5. The latency histogram, which categorizes requests based on latency buckets.
func GetMetrics() (int64, int64, int64, time.Duration, map[string]int64) {
	globalMetrics.mu.Lock()         // Locking the mutex to safely access the metrics.
	defer globalMetrics.mu.Unlock() // Ensure the mutex is unlocked once the function exits.
	// Returning the current values for requestCount, errorCount, successCount, totalLatency, and latencyHistogram.
	return globalMetrics.requestCount, globalMetrics.errorCount, globalMetrics.successCount, globalMetrics.totalLatency, globalMetrics.latencyHistogram
}

// ResetMetrics resets all metrics to zero.
// This method can be used for periodic reports or to clear metrics at specific intervals.
func ResetMetrics() {
	globalMetrics.mu.Lock()         // Locking the mutex to safely reset the metrics.
	defer globalMetrics.mu.Unlock() // Unlocking the mutex when done to allow other operations.
	// Resetting all counters to zero.
	globalMetrics.requestCount = 0
	globalMetrics.errorCount = 0
	globalMetrics.successCount = 0
	globalMetrics.totalLatency = 0
	// Reinitializing the latency histogram to an empty map.
	globalMetrics.latencyHistogram = make(map[string]int64)
}
