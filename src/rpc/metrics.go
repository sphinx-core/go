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
	"github.com/prometheus/client_golang/prometheus"
)

// NewMetrics initializes Prometheus metrics for the RPC server.
func NewMetrics() *Metrics {
	return &Metrics{
		RequestCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rpc_request_count",
				Help: "Number of RPC requests received",
			},
			[]string{"method"},
		),
		RequestLatency: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "rpc_request_latency_seconds",
				Help:    "Latency of RPC requests",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method"},
		),
		ErrorCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rpc_error_count",
				Help: "Number of RPC errors",
			},
			[]string{"method"},
		),
	}
}
