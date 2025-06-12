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

// go/src/rpc/metrics.go
package rpc

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	metrics     *Metrics  // Global pointer to hold Metrics instance
	initMetrics sync.Once // Ensures metrics initialization runs only once
)

// NewMetrics initializes and returns a singleton Metrics instance
func NewMetrics() *Metrics {
	initMetrics.Do(func() { // Execute the enclosed function only once, thread-safe
		metrics = &Metrics{ // Instantiate Metrics struct with Prometheus metrics
			RequestCount: promauto.NewCounterVec( // CounterVec for counting RPC requests per method
				prometheus.CounterOpts{
					Name: "rpc_request_total",                      // Metric name for total RPC requests
					Help: "Total number of RPC requests processed", // Metric description
				},
				[]string{"method"}, // Label to distinguish counts by RPC method
			),
			RequestLatency: promauto.NewHistogramVec( // HistogramVec for measuring RPC request latencies
				prometheus.HistogramOpts{
					Name:    "rpc_request_latency_seconds",        // Metric name for RPC latency
					Help:    "Latency of RPC requests in seconds", // Description for latency metric
					Buckets: prometheus.DefBuckets,                // Default buckets for histogram
				},
				[]string{"method"}, // Label to distinguish latencies by RPC method
			),
			ErrorCount: promauto.NewCounterVec( // CounterVec for counting RPC errors per method
				prometheus.CounterOpts{
					Name: "rpc_error_total",            // Metric name for total RPC errors
					Help: "Total number of RPC errors", // Description of error metric
				},
				[]string{"method"}, // Label to distinguish error counts by RPC method
			),
		}
		// Metrics created with promauto are automatically registered with Prometheus.
		// Therefore, explicit prometheus.MustRegister calls are not required here.
	})
	return metrics // Return the initialized Metrics pointer (singleton)
}
