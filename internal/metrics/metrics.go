// Package metrics provides a simple JSON metrics HTTP endpoint.
package metrics

import (
	"encoding/json"
	"net/http"
	"runtime"
	"sync/atomic"
	"time"
)

// limitExceededCounter accumulates DoS-limit breaches across all layers. It is a
// process-global atomic so any package (transport, grpc, confine) can bump it
// without holding a handler reference. It is surfaced in the /metrics JSON.
var limitExceededCounter atomic.Uint64

// IncLimitExceeded records one resource-limit breach of the given kind. kind is
// reserved for future per-kind breakdown; today it only increments the total.
func IncLimitExceeded(kind string) {
	_ = kind
	limitExceededCounter.Add(1)
}

// limitExceededTotal returns the current breach count (used by the handler and
// tests).
func limitExceededTotal() uint64 { return limitExceededCounter.Load() }

// LimitExceededTotalForTest exposes the breach counter to other packages' tests.
func LimitExceededTotalForTest() uint64 { return limitExceededTotal() }

// WorkerPoolStats is the interface the metrics handler uses to query the
// worker pool. Any type that exposes ActiveCount and TotalCount satisfies it.
type WorkerPoolStats interface {
	ActiveCount() int
	TotalCount() int
}

// Handler serves basic runtime and application metrics as JSON.
type Handler struct {
	startTime  time.Time
	workerPool WorkerPoolStats
}

type metricsResponse struct {
	UptimeSeconds float64 `json:"uptime_seconds"`
	GoVersion     string  `json:"go_version"`
	Goroutines    int     `json:"goroutines"`
	MemoryAllocMB float64 `json:"memory_alloc_mb"`
	WorkersActive      int    `json:"workers_active"`
	WorkersTotal       int    `json:"workers_total"`
	LimitExceededTotal uint64 `json:"limit_exceeded_total"`
}

// NewHandler creates a Handler that reports uptime from startTime and worker
// stats from the given pool. workerPool may be nil, in which case the worker
// fields are reported as zero.
func NewHandler(startTime time.Time, workerPool WorkerPoolStats) *Handler {
	return &Handler{
		startTime:  startTime,
		workerPool: workerPool,
	}
}

// ServeHTTP writes the metrics payload as JSON.
func (h *Handler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	resp := metricsResponse{
		UptimeSeconds: time.Since(h.startTime).Seconds(),
		GoVersion:     runtime.Version(),
		Goroutines:    runtime.NumGoroutine(),
		MemoryAllocMB: float64(m.Alloc) / (1024 * 1024),
	}

	if h.workerPool != nil {
		resp.WorkersActive = h.workerPool.ActiveCount()
		resp.WorkersTotal = h.workerPool.TotalCount()
	}

	resp.LimitExceededTotal = limitExceededTotal()

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
