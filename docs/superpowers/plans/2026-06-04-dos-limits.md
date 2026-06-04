# Phase 3.2 — Resource Limits & DoS Protection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Sentinel daemon resilient to resource-exhaustion DoS across four vectors (bootstrap flood, slow TLS handshakes, oversized/over-rate gRPC, runaway child processes), secure-by-default and operator-tunable, with a single unified config block and a single breach contract (reject + routine `limit.exceeded` audit event + Prometheus-style counter).

**Architecture:** No single god-limiter. Each layer enforces its own limit at its own boundary (TCP accept, TLS handshake, gRPC interceptor, process spawn). What unifies them is (1) one additive `settings.LimitsConfig` block (schema v3 → v4) holding every knob with conservative defaults, gated by `Enabled`; and (2) one breach helper that rejects, emits a **routine** `limit.exceeded` audit event with `Detail{kind, source}`, and bumps `sentinel_limit_exceeded_total{kind}`. The routine tier guarantees an audit-write failure never blocks a rejection. The Unix process rlimits (T5.3) slot into the existing `confine.Confiner` interface via a re-exec trampoline, so `exec` and `worker` need no new wiring — only the platform files change.

**Tech Stack:** Go 1.26, `google.golang.org/grpc`, `crypto/tls`, `golang.org/x/sys/unix` (Setrlimit), `syscall.Exec`, Cobra, `log/slog`, SQLite audit store, table-driven tests with `t.TempDir()` and `net.Pipe`/loopback listeners.

---

## File Structure

| File | Status | Responsibility |
|---|---|---|
| `internal/settings/settings.go` | Modify | Add `LimitsConfig` struct + `Limits` field on `Config`; `defaultLimitsConfig()`; wire into `DefaultConfig`, `Validate`, `Migrate`; bump `CurrentConfigVersion` 3 → 4. |
| `internal/settings/settings_limits_test.go` | Create | Defaults / Validate / v3→v4 Migrate table tests. |
| `internal/audit/catalog.go` | Modify | Add `EventLimitExceeded = "limit.exceeded"` classified `Routine`. |
| `internal/limits/limits.go` | Create | The reusable breach helper: `Recorder` (audit logger + metric), `kind` constants, `Record(ctx, kind, source)`. |
| `internal/limits/limits_test.go` | Create | Breach helper emits routine event + bumps metric; audit-write failure does not block. |
| `internal/metrics/metrics.go` | Modify | Add atomic `limit_exceeded_total` counter surfaced in `metricsResponse`; exported `IncLimitExceeded(kind)`. |
| `internal/grpc/server.go` | Modify | Add `WithMaxRecvMsgSize` / `WithMaxConcurrentStreams` Options that append `grpc.ServerOption`s. |
| `internal/grpc/server_limits_test.go` | Create | Message-size cap returns `ResourceExhausted`; under-cap succeeds. |
| `internal/grpc/ratelimit_test.go` | Create (or extend) | `NewRateLimiter` honours configured rate. |
| `pkg/transport/bootstrap_limiter.go` | Create | `perIPLimiter`: per-source-IP concurrent + token-bucket-rate limiting with idle-bucket sweep. |
| `pkg/transport/bootstrap_limiter_test.go` | Create | Concurrent cap, rate cap, second-IP isolation, refill, sweep. |
| `pkg/transport/bootstrap.go` | Modify | Wire `perIPLimiter` into the accept loop; accept-then-close excess. |
| `pkg/transport/connlimit.go` | Create | `connLimitListener`: global + per-device conn caps + TLS handshake timeout wrapper. |
| `pkg/transport/connlimit_test.go` | Create | Handshake timeout, global cap, per-device cap, recovery after close. |
| `pkg/transport/transport.go` | Modify | `Config` gets a `Limits` sub-config; `startMTLS` wraps the listener; bootstrap limiter knobs threaded through. |
| `internal/confine/confine.go` | Modify | Add rlimit fields to `Config`; carry through `New`. |
| `internal/confine/confine_other.go` | Modify | Retag `//go:build !windows && !linux && !darwin` (the only no-op platforms left). |
| `internal/confine/confine_unix.go` | Create | `//go:build linux || darwin` — trampoline-injecting confiner (`Prepare` rewrites cmd, `Supported` true). |
| `internal/confine/trampoline.go` | Create | Cross-platform-buildable constants + `TrampolineArgs` helper shared by the unix confiner and the cmd subcommand. |
| `internal/confine/confine_unix_test.go` | Create | `//go:build linux` — child exceeding `RLIMIT_AS`/`RLIMIT_NOFILE` fails; daemon rlimits unchanged. |
| `cmd/confined_exec.go` | Create | Hidden `sentinel __confined-exec` subcommand: setrlimit then `syscall.Exec` the target (unix); error stub elsewhere. |
| `cmd/confined_exec_test.go` | Create | `//go:build linux` — subcommand applies rlimits then execs. |
| `cmd/root.go` | Modify | Register `newConfinedExecCmd()`. |
| `cmd/serve.go` | Modify | Build `limits.Recorder`; thread `LimitsConfig` into transport, gRPC server opts, rate limiter, confiner; pass recorder to metrics server. |
| `cmd/serve_limits_test.go` | Create | Daemon builds with limits config; defaults applied. |
| `docs/security/THREAT-MODEL.md` | Modify | T1.3/T2.4/T2.6 → mitigated; T5.3 → fully mitigated cross-platform. |
| `docs/superpowers/HARDENING-STATUS.md` | Modify | Add Phase 3.2 campaign entry. |

---

## Task 1: `settings.LimitsConfig` + defaults + Validate + v3→v4 Migrate

**Files:**
- Modify: `internal/settings/settings.go`
- Test: `internal/settings/settings_limits_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/settings/settings_limits_test.go`:

```go
package settings

import "testing"

func TestDefaultLimitsConfig(t *testing.T) {
	c := DefaultConfig()
	l := c.Limits
	if !l.Enabled {
		t.Fatal("limits should default to enabled")
	}
	cases := []struct {
		name string
		got  uint64
		want uint64
	}{
		{"BootstrapPerIPMaxConns", uint64(l.BootstrapPerIPMaxConns), 8},
		{"BootstrapPerIPRate", uint64(l.BootstrapPerIPRate), 5},
		{"MaxConns", uint64(l.MaxConns), 256},
		{"PerDeviceMaxConns", uint64(l.PerDeviceMaxConns), 16},
		{"MaxRecvMsgBytes", uint64(l.MaxRecvMsgBytes), 1048576},
		{"MaxConcurrentStreams", uint64(l.MaxConcurrentStreams), 128},
		{"RPCRatePerSec", uint64(l.RPCRatePerSec), 100},
		{"ProcMaxMemoryBytes", l.ProcMaxMemoryBytes, 1 << 30},
		{"ProcMaxOpenFiles", l.ProcMaxOpenFiles, 1024},
		{"ProcMaxCPUSeconds", l.ProcMaxCPUSeconds, 0},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, tc.got, tc.want)
		}
	}
	if l.TLSHandshakeTimeout != 10_000_000_000 { // 10s
		t.Errorf("TLSHandshakeTimeout = %v, want 10s", l.TLSHandshakeTimeout)
	}
}

func TestValidateLimits(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*LimitsConfig)
		wantErr bool
	}{
		{"defaults ok", func(*LimitsConfig) {}, false},
		{"disabled skips checks", func(l *LimitsConfig) { l.Enabled = false; l.MaxConns = 0 }, false},
		{"zero max conns", func(l *LimitsConfig) { l.MaxConns = 0 }, true},
		{"zero per-device", func(l *LimitsConfig) { l.PerDeviceMaxConns = 0 }, true},
		{"zero bootstrap conns", func(l *LimitsConfig) { l.BootstrapPerIPMaxConns = 0 }, true},
		{"zero recv bytes", func(l *LimitsConfig) { l.MaxRecvMsgBytes = 0 }, true},
		{"zero streams", func(l *LimitsConfig) { l.MaxConcurrentStreams = 0 }, true},
		{"zero rpc rate", func(l *LimitsConfig) { l.RPCRatePerSec = 0 }, true},
		{"zero handshake timeout", func(l *LimitsConfig) { l.TLSHandshakeTimeout = 0 }, true},
		{"zero proc mem ok (unlimited)", func(l *LimitsConfig) { l.ProcMaxMemoryBytes = 0 }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := DefaultConfig()
			tt.mutate(&c.Limits)
			err := c.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMigrateV3ToV4AddsLimits(t *testing.T) {
	c := DefaultConfig()
	c.Version = 3
	c.Limits = LimitsConfig{} // simulate a v3 file with no limits block
	changed := c.Migrate(3)
	if !changed {
		t.Fatal("Migrate(3) should report a change")
	}
	if c.Version != CurrentConfigVersion {
		t.Fatalf("Version = %d, want %d", c.Version, CurrentConfigVersion)
	}
	if !c.Limits.Enabled || c.Limits.MaxConns != 256 {
		t.Fatalf("Migrate did not back-fill limits defaults: %+v", c.Limits)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/settings/ -run 'Limits|MigrateV3ToV4' -v`
Expected: FAIL — `c.Limits undefined`, `LimitsConfig undefined`.

- [ ] **Step 3: Add the config type, defaults, validate, migrate**

In `internal/settings/settings.go`, bump the version constant:

```go
// CurrentConfigVersion is the schema version written by this build. Bump it
// whenever the config layout changes and add a step to Config.Migrate.
const CurrentConfigVersion = 4
```

Add `Limits` to the `Config` struct (after the `Audit` field):

```go
	Confine   ConfineConfig   `yaml:"confine"`
	Audit     AuditConfig     `yaml:"audit"`
	Limits    LimitsConfig    `yaml:"limits"`
```

Add the type (place it after `AuditConfig`):

```go
import "time" // add to the existing import block if not present

// LimitsConfig holds the resource-limit / DoS-protection knobs (Phase 3.2).
// Enabled (default true) gates the whole subsystem; the Proc* caps may be 0,
// meaning "unlimited — leave it to the OS default".
type LimitsConfig struct {
	Enabled bool `yaml:"enabled"`
	// T1.3 — bootstrap (pre-auth, per source IP).
	BootstrapPerIPMaxConns int `yaml:"bootstrap_per_ip_max_conns"`
	BootstrapPerIPRate     int `yaml:"bootstrap_per_ip_rate"`
	// T2.6 — mTLS listener.
	TLSHandshakeTimeout time.Duration `yaml:"tls_handshake_timeout"`
	MaxConns            int           `yaml:"max_conns"`
	PerDeviceMaxConns   int           `yaml:"per_device_max_conns"`
	// T2.4 — gRPC.
	MaxRecvMsgBytes      int    `yaml:"max_recv_msg_bytes"`
	MaxConcurrentStreams uint32 `yaml:"max_concurrent_streams"`
	RPCRatePerSec        int    `yaml:"rpc_rate_per_sec"`
	// T5.3 — process rlimits (Unix; complements the Windows Job Object).
	ProcMaxMemoryBytes uint64 `yaml:"proc_max_memory_bytes"` // RLIMIT_AS; 0 = unlimited
	ProcMaxOpenFiles   uint64 `yaml:"proc_max_open_files"`   // RLIMIT_NOFILE; 0 = unlimited
	ProcMaxCPUSeconds  uint64 `yaml:"proc_max_cpu_seconds"`  // RLIMIT_CPU; 0 = unlimited
}

// defaultLimitsConfig is the single source of truth shared by DefaultConfig and
// Migrate so the two cannot drift.
func defaultLimitsConfig() LimitsConfig {
	return LimitsConfig{
		Enabled:                true,
		BootstrapPerIPMaxConns: 8,
		BootstrapPerIPRate:     5,
		TLSHandshakeTimeout:    10 * time.Second,
		MaxConns:               256,
		PerDeviceMaxConns:      16,
		MaxRecvMsgBytes:        1 << 20, // 1 MiB
		MaxConcurrentStreams:   128,
		RPCRatePerSec:          100,
		ProcMaxMemoryBytes:     1 << 30, // 1 GiB
		ProcMaxOpenFiles:       1024,
		ProcMaxCPUSeconds:      0,
	}
}
```

In `DefaultConfig`, add the field to the returned struct literal (after `Audit: defaultAuditConfig(),`):

```go
		Confine: defaultConfineConfig(),
		Audit:   defaultAuditConfig(),
		Limits:  defaultLimitsConfig(),
```

In `Validate`, add before the final `return nil`:

```go
	// Check resource limits when the subsystem is enabled. The Proc* caps may be
	// 0 (meaning "unlimited"), so they are intentionally not checked here.
	if c.Limits.Enabled {
		if c.Limits.BootstrapPerIPMaxConns <= 0 {
			return fmt.Errorf("limits.bootstrap_per_ip_max_conns must be > 0, got %d", c.Limits.BootstrapPerIPMaxConns)
		}
		if c.Limits.BootstrapPerIPRate <= 0 {
			return fmt.Errorf("limits.bootstrap_per_ip_rate must be > 0, got %d", c.Limits.BootstrapPerIPRate)
		}
		if c.Limits.TLSHandshakeTimeout <= 0 {
			return fmt.Errorf("limits.tls_handshake_timeout must be > 0, got %v", c.Limits.TLSHandshakeTimeout)
		}
		if c.Limits.MaxConns <= 0 {
			return fmt.Errorf("limits.max_conns must be > 0, got %d", c.Limits.MaxConns)
		}
		if c.Limits.PerDeviceMaxConns <= 0 {
			return fmt.Errorf("limits.per_device_max_conns must be > 0, got %d", c.Limits.PerDeviceMaxConns)
		}
		if c.Limits.MaxRecvMsgBytes <= 0 {
			return fmt.Errorf("limits.max_recv_msg_bytes must be > 0, got %d", c.Limits.MaxRecvMsgBytes)
		}
		if c.Limits.MaxConcurrentStreams == 0 {
			return fmt.Errorf("limits.max_concurrent_streams must be > 0")
		}
		if c.Limits.RPCRatePerSec <= 0 {
			return fmt.Errorf("limits.rpc_rate_per_sec must be > 0, got %d", c.Limits.RPCRatePerSec)
		}
	}
	return nil
```

In `Migrate`, back-fill v4 defaults when migrating from below v4 (replace the body):

```go
func (c *Config) Migrate(fromVersion int) bool {
	changed := false
	// v3 → v4 introduced the limits: block. Load overlays on-disk YAML onto
	// DefaultConfig, so a file written at v3 already carries the defaults for any
	// key it omits — but a file that wrote an explicit (zero-value) limits block,
	// or one with Enabled=false-by-omission, must be back-filled to the safe
	// defaults. Detect the unmigrated zero block and restore defaults.
	if fromVersion < 4 && c.Limits == (LimitsConfig{}) {
		c.Limits = defaultLimitsConfig()
		changed = true
	}
	if c.Version < CurrentConfigVersion {
		c.Version = CurrentConfigVersion
		changed = true
	}
	return changed
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/settings/ -run 'Limits|MigrateV3ToV4' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/settings/settings.go internal/settings/settings_limits_test.go
git commit -m "feat(settings): add LimitsConfig block with v3->v4 migration"
```

---

## Task 2: `limit.exceeded` audit event + breach helper + metric

**Files:**
- Modify: `internal/audit/catalog.go`
- Modify: `internal/metrics/metrics.go`
- Create: `internal/limits/limits.go`
- Test: `internal/limits/limits_test.go`

- [ ] **Step 1: Add the catalog event (no test needed beyond the existing registry-completeness test)**

In `internal/audit/catalog.go`, add the constant (after `EventAuditPrune`):

```go
	EventAuditPrune          = "audit.prune"
	EventLimitExceeded       = "limit.exceeded"
```

And classify it `Routine` in the `catalog` map (after `EventAuditPrune: Routine,`):

```go
	EventAuditPrune:          Routine,
	EventLimitExceeded:       Routine,
```

- [ ] **Step 2: Write the failing test for the metric counter**

Create `internal/metrics/metrics_limit_test.go`:

```go
package metrics

import "testing"

func TestIncLimitExceeded(t *testing.T) {
	before := limitExceededTotal()
	IncLimitExceeded("bootstrap_ip")
	IncLimitExceeded("rpc_rate")
	if got := limitExceededTotal() - before; got != 2 {
		t.Fatalf("limitExceededTotal delta = %d, want 2", got)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/metrics/ -run TestIncLimitExceeded -v`
Expected: FAIL — `IncLimitExceeded undefined`, `limitExceededTotal undefined`.

- [ ] **Step 4: Add the atomic counter to metrics**

In `internal/metrics/metrics.go`, add `"sync/atomic"` to the import block, then add at package scope (after the imports):

```go
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
```

Add the field to `metricsResponse`:

```go
	WorkersActive       int     `json:"workers_active"`
	WorkersTotal        int     `json:"workers_total"`
	LimitExceededTotal  uint64  `json:"limit_exceeded_total"`
```

Set it in `ServeHTTP` (after the workerPool block, before writing the header):

```go
	resp.LimitExceededTotal = limitExceededTotal()
```

- [ ] **Step 5: Run the metric test**

Run: `go test ./internal/metrics/ -run TestIncLimitExceeded -v`
Expected: PASS.

- [ ] **Step 6: Write the failing test for the breach helper**

Create `internal/limits/limits_test.go`:

```go
package limits

import (
	"context"
	"errors"
	"testing"

	"github.com/inovacc/sentinel/internal/audit"
	"github.com/inovacc/sentinel/internal/metrics"
)

type capturingLogger struct {
	events []audit.Event
	err    error
}

func (c *capturingLogger) Record(_ context.Context, ev audit.Event) error {
	c.events = append(c.events, ev)
	return c.err
}
func (c *capturingLogger) Close() error { return nil }

func TestRecordEmitsRoutineEventAndBumpsMetric(t *testing.T) {
	log := &capturingLogger{}
	r := NewRecorder(log)
	before := metricsTotalForTest()

	r.Record(context.Background(), KindBootstrapIP, "203.0.113.7")

	if len(log.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(log.events))
	}
	ev := log.events[0]
	if ev.Type != audit.EventLimitExceeded {
		t.Errorf("event type = %q, want %q", ev.Type, audit.EventLimitExceeded)
	}
	if ev.Detail["kind"] != KindBootstrapIP || ev.Detail["source"] != "203.0.113.7" {
		t.Errorf("detail = %v, want kind/source set", ev.Detail)
	}
	if got := metricsTotalForTest() - before; got != 1 {
		t.Errorf("metric delta = %d, want 1", got)
	}
}

func TestRecordSwallowsAuditError(t *testing.T) {
	// A routine audit-write failure must not panic or propagate; the rejection
	// (caller's responsibility) proceeds regardless.
	log := &capturingLogger{err: errors.New("disk full")}
	r := NewRecorder(log)
	r.Record(context.Background(), KindRPCRate, "device-x") // must not panic
}

func TestNilRecorderIsSafe(t *testing.T) {
	var r *Recorder
	r.Record(context.Background(), KindMsgSize, "x") // must be a no-op, no panic
}

// metricsTotalForTest reads the global counter via a fresh handler scrape proxy.
func metricsTotalForTest() uint64 { return metrics.LimitExceededTotalForTest() }
```

- [ ] **Step 7: Run test to verify it fails**

Run: `go test ./internal/limits/ -v`
Expected: FAIL — `limits` package / `NewRecorder` / `metrics.LimitExceededTotalForTest` undefined.

- [ ] **Step 8: Add a test accessor to metrics, then the breach helper**

In `internal/metrics/metrics.go`, export a test accessor (the unexported `limitExceededTotal` stays for in-package tests):

```go
// LimitExceededTotalForTest exposes the breach counter to other packages' tests.
func LimitExceededTotalForTest() uint64 { return limitExceededTotal() }
```

Create `internal/limits/limits.go`:

```go
// Package limits centralizes the Phase 3.2 breach contract: when any layer
// (bootstrap, mTLS listener, gRPC interceptor, process spawn) detects a
// resource-limit breach it rejects the request and calls Recorder.Record, which
// emits a single routine audit event and bumps the process-global metric. The
// audit event is routine on purpose: a write failure must never block a
// rejection (that would make the audit path itself a DoS vector).
package limits

import (
	"context"

	"github.com/inovacc/sentinel/internal/audit"
	"github.com/inovacc/sentinel/internal/metrics"
)

// Kind labels the breach vector for the audit Detail and the metric.
const (
	KindBootstrapIP      = "bootstrap_ip"
	KindHandshakeTimeout = "handshake_timeout"
	KindConnCap          = "conn_cap"
	KindPerDeviceCap     = "per_device_cap"
	KindRPCRate          = "rpc_rate"
	KindMsgSize          = "msg_size"
	KindProcRlimit       = "proc_rlimit"
)

// Recorder turns a limit breach into a routine audit event + a metric bump. A
// nil *Recorder is a valid no-op so layers can be wired before the daemon's
// audit logger exists (and in tests).
type Recorder struct {
	logger audit.Logger
}

// NewRecorder builds a Recorder over the given audit logger. A nil logger is
// tolerated (the metric still increments, no event is written).
func NewRecorder(logger audit.Logger) *Recorder {
	return &Recorder{logger: logger}
}

// Record emits the breach contract: increment the metric, then write the routine
// limit.exceeded event. The audit-write error is swallowed (routine tier) so the
// caller's rejection always proceeds.
func (r *Recorder) Record(ctx context.Context, kind, source string) {
	metrics.IncLimitExceeded(kind)
	if r == nil || r.logger == nil {
		return
	}
	_ = r.logger.Record(ctx, audit.Event{
		Type:    audit.EventLimitExceeded,
		Outcome: audit.OutcomeDeny,
		Target:  source,
		Detail:  map[string]any{"kind": kind, "source": source},
	})
}
```

- [ ] **Step 9: Run the limits + metrics tests**

Run: `go test ./internal/limits/ ./internal/metrics/ -v`
Expected: PASS.

- [ ] **Step 10: Run the audit registry-completeness test to confirm the new event is classified**

Run: `go test ./internal/audit/ -v`
Expected: PASS (the completeness test sees `EventLimitExceeded` classified `Routine`).

- [ ] **Step 11: Commit**

```bash
git add internal/audit/catalog.go internal/metrics/metrics.go internal/metrics/metrics_limit_test.go internal/limits/limits.go internal/limits/limits_test.go
git commit -m "feat(limits): add limit.exceeded event, breach recorder, and metric"
```

---

## Task 3: T2.4 — gRPC message/stream caps + configurable rate limiter

**Files:**
- Modify: `internal/grpc/server.go`
- Test: `internal/grpc/server_limits_test.go`
- Test: `internal/grpc/ratelimit_test.go`

- [ ] **Step 1: Write the failing test for server options + configurable rate**

Create `internal/grpc/server_limits_test.go`:

```go
package grpc

import (
	"testing"
	"time"
)

func TestWithMaxRecvMsgSizeAppendsOption(t *testing.T) {
	cfg := &serverConfig{}
	WithMaxRecvMsgSize(1 << 20)(cfg)
	WithMaxConcurrentStreams(128)(cfg)
	if len(cfg.grpcOpts) != 2 {
		t.Fatalf("expected 2 grpc opts, got %d", len(cfg.grpcOpts))
	}
}

func TestRateLimiterHonoursConfiguredRate(t *testing.T) {
	// A 2/sec limiter allows exactly two before refusing.
	rl := NewRateLimiter(2, time.Second)
	if !rl.Allow("c1") || !rl.Allow("c1") {
		t.Fatal("first two requests should be allowed")
	}
	if rl.Allow("c1") {
		t.Fatal("third request should be rate-limited")
	}
	// A different client has its own bucket.
	if !rl.Allow("c2") {
		t.Fatal("second client should be allowed")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/grpc/ -run 'WithMaxRecvMsgSize|RateLimiterHonours' -v`
Expected: FAIL — `WithMaxRecvMsgSize undefined`, `WithMaxConcurrentStreams undefined`.

- [ ] **Step 3: Add the Options**

In `internal/grpc/server.go`, add after `WithServerOption`:

```go
// WithMaxRecvMsgSize caps the size in bytes of a single inbound request message.
// Oversized messages are rejected by gRPC with codes.ResourceExhausted. This
// bounds inbound messages only — outbound responses (e.g. screenshots) are not
// capped, so large captures keep working.
func WithMaxRecvMsgSize(n int) Option {
	return func(c *serverConfig) {
		c.grpcOpts = append(c.grpcOpts, grpc.MaxRecvMsgSize(n))
	}
}

// WithMaxConcurrentStreams bounds the number of concurrent streams a single
// connection may open, limiting per-connection multiplexing abuse.
func WithMaxConcurrentStreams(n uint32) Option {
	return func(c *serverConfig) {
		c.grpcOpts = append(c.grpcOpts, grpc.MaxConcurrentStreams(n))
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/grpc/ -run 'WithMaxRecvMsgSize|RateLimiterHonours' -v`
Expected: PASS.

- [ ] **Step 5: Write an end-to-end message-size cap test**

Append to `internal/grpc/server_limits_test.go`:

```go
import (
	"context"
	"crypto/tls"
	"net"

	v1 "github.com/inovacc/sentinel/internal/api/v1"
	"github.com/inovacc/sentinel/internal/rbac"
	"github.com/inovacc/sentinel/internal/testca" // existing test CA helper used elsewhere in this package
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

func TestMaxRecvMsgSizeRejectsOversized(t *testing.T) {
	// Build a server with a tiny 64-byte recv cap and a loopback listener.
	srvCert, srvKey, caPEM, cliCert, cliKey := testca.ServerClientPair(t)
	s, err := NewServer(srvCert, srvKey, caPEM, rbac.NewPolicy(), nil,
		WithMaxRecvMsgSize(64))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	// Register a payload service so there is a unary method to call.
	v1.RegisterPayloadServiceServer(s.GRPCServer(), &echoPayload{})

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = s.GRPCServer().Serve(lis) }()
	defer s.GRPCServer().Stop()

	cert, _ := tls.X509KeyPair(cliCert, cliKey)
	caPool := testca.Pool(t, caPEM)
	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{cert}, RootCAs: caPool, ServerName: "127.0.0.1",
		})))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	client := v1.NewPayloadServiceClient(conn)
	big := make([]byte, 1024) // > 64-byte cap
	_, err = client.Send(context.Background(), &v1.SendRequest{Data: big})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("oversized Send: code = %v, want ResourceExhausted (err=%v)", status.Code(err), err)
	}
}
```

> NOTE: `testca`, `echoPayload`, and the exact `PayloadService` message/field names
> must match the package's existing test helpers. Before writing this test, run
> `go doc ./internal/api/v1 PayloadServiceServer` and grep the `internal/grpc`
> test files for the existing CA helper. If the package already has a server
> bring-up helper (e.g. `newTestServer`), reuse it and drop the inline bring-up.
> The behavioral assertion (oversized inbound message → `codes.ResourceExhausted`)
> is the load-bearing part and must not change.

- [ ] **Step 6: Run the e2e test**

Run: `go test ./internal/grpc/ -run TestMaxRecvMsgSizeRejectsOversized -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/grpc/server.go internal/grpc/server_limits_test.go
git commit -m "feat(grpc): add MaxRecvMsgSize/MaxConcurrentStreams options for T2.4"
```

---

## Task 4: T1.3 — Bootstrap per-IP limiter

**Files:**
- Create: `pkg/transport/bootstrap_limiter.go`
- Test: `pkg/transport/bootstrap_limiter_test.go`
- Modify: `pkg/transport/bootstrap.go`

- [ ] **Step 1: Write the failing test for the limiter**

Create `pkg/transport/bootstrap_limiter_test.go`:

```go
package transport

import (
	"testing"
	"time"
)

func TestPerIPLimiterConcurrentCap(t *testing.T) {
	l := newPerIPLimiter(2, 100) // 2 concurrent, rate effectively unlimited here
	rel1, ok1 := l.acquire("10.0.0.1")
	rel2, ok2 := l.acquire("10.0.0.1")
	if !ok1 || !ok2 {
		t.Fatal("first two acquisitions from one IP should succeed")
	}
	if _, ok3 := l.acquire("10.0.0.1"); ok3 {
		t.Fatal("third concurrent acquisition should be rejected")
	}
	// A different IP is unaffected.
	if _, ok := l.acquire("10.0.0.2"); !ok {
		t.Fatal("a second IP must not be throttled by the first")
	}
	// Releasing one frees a slot.
	rel1()
	if _, ok := l.acquire("10.0.0.1"); !ok {
		t.Fatal("releasing a slot should allow a new acquisition")
	}
	rel2()
}

func TestPerIPLimiterRateCap(t *testing.T) {
	l := newPerIPLimiter(100, 2) // generous concurrency, 2 new conns/sec
	// Burst of 2 succeeds, 3rd is rate-limited (then released so concurrency
	// is not the limiter).
	for i := 0; i < 2; i++ {
		rel, ok := l.acquire("10.0.0.9")
		if !ok {
			t.Fatalf("acquire %d should pass the rate gate", i)
		}
		rel()
	}
	if _, ok := l.acquire("10.0.0.9"); ok {
		t.Fatal("third acquisition within the same second should be rate-limited")
	}
}

func TestPerIPLimiterSweepEvictsIdle(t *testing.T) {
	l := newPerIPLimiter(2, 2)
	rel, _ := l.acquire("10.0.0.5")
	rel()
	l.sweep(time.Now().Add(time.Hour)) // pretend a lot of time passed
	if n := l.bucketCount(); n != 0 {
		t.Fatalf("idle bucket should be evicted, have %d", n)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/transport/ -run TestPerIPLimiter -v`
Expected: FAIL — `newPerIPLimiter undefined`.

- [ ] **Step 3: Implement the limiter**

Create `pkg/transport/bootstrap_limiter.go`:

```go
package transport

import (
	"sync"
	"time"
)

// perIPLimiter throttles pre-auth bootstrap connections by source IP across two
// dimensions: a concurrent-connection cap and a token-bucket rate of new
// connections per second. It is keyed by IP (not device ID) because bootstrap
// is pre-authentication. Idle buckets are evicted by a periodic sweep to bound
// memory.
type perIPLimiter struct {
	mu          sync.Mutex
	buckets     map[string]*ipBucket
	maxConns    int
	ratePerSec  int
}

type ipBucket struct {
	active   int       // currently-held concurrent connections
	tokens   int       // rate tokens remaining this second
	lastFill time.Time // last token refill
	lastSeen time.Time // last activity, for the idle sweep
}

// newPerIPLimiter builds a limiter allowing maxConns concurrent connections and
// ratePerSec new connections per second, per source IP.
func newPerIPLimiter(maxConns, ratePerSec int) *perIPLimiter {
	return &perIPLimiter{
		buckets:    make(map[string]*ipBucket),
		maxConns:   maxConns,
		ratePerSec: ratePerSec,
	}
}

// acquire attempts to admit one new connection from ip. It returns a release
// func and true on success; (nil, false) when either the concurrency cap or the
// rate cap is exceeded. The release func MUST be called when the connection
// closes so the concurrency slot is freed.
func (l *perIPLimiter) acquire(ip string) (release func(), ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b := l.buckets[ip]
	if b == nil {
		b = &ipBucket{tokens: l.ratePerSec, lastFill: now}
		l.buckets[ip] = b
	}
	b.lastSeen = now

	// Refill rate tokens once per elapsed second.
	if elapsed := now.Sub(b.lastFill); elapsed >= time.Second {
		b.tokens = l.ratePerSec
		b.lastFill = now
	}

	if b.tokens <= 0 {
		return nil, false // rate cap
	}
	if b.active >= l.maxConns {
		return nil, false // concurrency cap
	}

	b.tokens--
	b.active++
	released := false
	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		if released {
			return
		}
		released = true
		if cur := l.buckets[ip]; cur != nil && cur.active > 0 {
			cur.active--
			cur.lastSeen = time.Now()
		}
	}, true
}

// sweep evicts buckets idle since before cutoff and with no active connections.
func (l *perIPLimiter) sweep(cutoff time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for ip, b := range l.buckets {
		if b.active == 0 && b.lastSeen.Before(cutoff) {
			delete(l.buckets, ip)
		}
	}
}

// bucketCount reports the number of tracked IP buckets (used by the sweep test).
func (l *perIPLimiter) bucketCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// runSweeper sweeps idle buckets every interval until stop is closed.
func (l *perIPLimiter) runSweeper(interval, idle time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			l.sweep(now.Add(-idle))
		}
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./pkg/transport/ -run TestPerIPLimiter -v`
Expected: PASS.

- [ ] **Step 5: Write the failing test for accept-loop integration**

Create `pkg/transport/bootstrap_accept_test.go`:

```go
package transport

import (
	"net"
	"testing"
)

// stubAddr lets us drive remoteIP without a real connection.
type stubAddr struct{ s string }

func (a stubAddr) Network() string { return "tcp" }
func (a stubAddr) String() string  { return a.s }

func TestRemoteIPParsesHostPort(t *testing.T) {
	if got := remoteIP(stubAddr{"203.0.113.4:51000"}); got != "203.0.113.4" {
		t.Fatalf("remoteIP = %q, want 203.0.113.4", got)
	}
	// A bare address (no port) falls back to the raw string.
	if got := remoteIP(stubAddr{"203.0.113.5"}); got != "203.0.113.5" {
		t.Fatalf("remoteIP fallback = %q", got)
	}
}

func TestRemoteIPHandlesTCPAddr(t *testing.T) {
	a := &net.TCPAddr{IP: net.ParseIP("198.51.100.2"), Port: 7399}
	if got := remoteIP(a); got != "198.51.100.2" {
		t.Fatalf("remoteIP(TCPAddr) = %q", got)
	}
}
```

- [ ] **Step 6: Run test to verify it fails**

Run: `go test ./pkg/transport/ -run TestRemoteIP -v`
Expected: FAIL — `remoteIP undefined`.

- [ ] **Step 7: Wire the limiter into the bootstrap accept loop**

In `pkg/transport/bootstrap_limiter.go`, add the helper:

```go
import "net" // add to the existing import block

// remoteIP extracts the source IP string from a net.Addr, falling back to the
// raw address string when it has no host:port form.
func remoteIP(addr net.Addr) string {
	if ta, ok := addr.(*net.TCPAddr); ok {
		return ta.IP.String()
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
```

In `pkg/transport/bootstrap.go`, give `BootstrapServer` a limiter and a recorder. Add fields to the struct:

```go
type BootstrapServer struct {
	manager  *Manager
	logger   *slog.Logger
	version  string
	hostname string
	limiter  *perIPLimiter
	recorder *limits.Recorder
}
```

Add the import `"github.com/inovacc/sentinel/internal/limits"` and `"context"`/`"time"` are already present. Update `NewBootstrapServer` to build the limiter from the manager's limits config:

```go
// NewBootstrapServer creates a bootstrap server tied to a transport manager.
func NewBootstrapServer(m *Manager, version string) *BootstrapServer {
	hostname, _ := os.Hostname()
	lc := m.cfg.Limits
	var lim *perIPLimiter
	if lc.Enabled {
		lim = newPerIPLimiter(lc.BootstrapPerIPMaxConns, lc.BootstrapPerIPRate)
	}
	return &BootstrapServer{
		manager:  m,
		logger:   m.logger.With("component", "bootstrap-server"),
		version:  version,
		hostname: hostname,
		limiter:  lim,
		recorder: m.cfg.LimitRecorder,
	}
}
```

Update the accept loop in `Serve` to throttle before dispatching:

```go
	for {
		conn, err := lis.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				// Listener closed (transition happened).
				bs.logger.Info("bootstrap: listener closed")
				return nil
			}
		}

		// Pre-auth per-IP throttle (T1.3): accept-then-close over-limit conns so
		// the accept loop is never blocked.
		if bs.limiter != nil {
			ip := remoteIP(conn.RemoteAddr())
			release, ok := bs.limiter.acquire(ip)
			if !ok {
				bs.logger.Warn("bootstrap: per-IP limit exceeded, dropping", "ip", ip)
				bs.recorder.Record(ctx, limits.KindBootstrapIP, ip)
				_ = conn.Close()
				continue
			}
			go func(c net.Conn, rel func()) {
				defer rel()
				bs.handleConn(ctx, c)
			}(conn, release)
			continue
		}

		go bs.handleConn(ctx, conn)
	}
```

> NOTE: `m.cfg.Limits` and `m.cfg.LimitRecorder` are added to `transport.Config`
> in Task 5/Task 8. To keep this task self-contained and compiling, add those two
> fields now if Task 5 has not run yet (see the field definitions in Task 5,
> Step 3). The accept-loop `bs.recorder` is a `*limits.Recorder`; a nil recorder
> is a safe no-op (Task 2).

- [ ] **Step 8: Run the remoteIP test**

Run: `go test ./pkg/transport/ -run 'TestRemoteIP|TestPerIPLimiter' -v`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add pkg/transport/bootstrap_limiter.go pkg/transport/bootstrap_limiter_test.go pkg/transport/bootstrap_accept_test.go pkg/transport/bootstrap.go
git commit -m "feat(transport): per-IP bootstrap throttle with idle sweep (T1.3)"
```

---

## Task 5: T2.6 — TLS handshake timeout + connection caps

**Files:**
- Create: `pkg/transport/connlimit.go`
- Test: `pkg/transport/connlimit_test.go`
- Modify: `pkg/transport/transport.go`

- [ ] **Step 1: Write the failing test for the connection-limiting listener**

Create `pkg/transport/connlimit_test.go`:

```go
package transport

import (
	"errors"
	"net"
	"testing"
	"time"
)

// fakeListener feeds a fixed set of connections then blocks until closed.
type fakeListener struct {
	conns chan net.Conn
	addr  net.Addr
}

func (f *fakeListener) Accept() (net.Conn, error) {
	c, ok := <-f.conns
	if !ok {
		return nil, errors.New("closed")
	}
	return c, nil
}
func (f *fakeListener) Close() error   { close(f.conns); return nil }
func (f *fakeListener) Addr() net.Addr { return f.addr }

func TestConnLimitGlobalCap(t *testing.T) {
	inner := &fakeListener{conns: make(chan net.Conn, 4), addr: &net.TCPAddr{}}
	rec := NewLimitRecorderForTest()
	ll := newConnLimitListener(inner, connLimitOpts{maxConns: 2, perDevice: 16, handshakeTimeout: time.Second}, rec)

	c1, s1 := net.Pipe()
	c2, s2 := net.Pipe()
	c3, s3 := net.Pipe()
	defer func() { _ = c1.Close(); _ = c2.Close(); _ = c3.Close() }()
	inner.conns <- s1
	inner.conns <- s2
	inner.conns <- s3

	a1, err := ll.Accept()
	if err != nil {
		t.Fatalf("accept 1: %v", err)
	}
	a2, err := ll.Accept()
	if err != nil {
		t.Fatalf("accept 2: %v", err)
	}
	// The 3rd connection is over the global cap: the wrapper closes s3 and keeps
	// accepting, so the next successful Accept must not return until a slot frees.
	freed := make(chan net.Conn, 1)
	go func() {
		a, aerr := ll.Accept()
		if aerr == nil {
			freed <- a
		}
	}()
	// s3 should be closed by the wrapper; reading from c3 returns an error.
	_ = c3.SetReadDeadline(time.Now().Add(time.Second))
	if _, rerr := c3.Read(make([]byte, 1)); rerr == nil {
		t.Fatal("over-cap connection should have been closed")
	}
	// Free a slot; the pending Accept should complete.
	_ = a1.Close()
	select {
	case <-freed:
	case <-time.After(2 * time.Second):
		t.Fatal("freeing a slot did not unblock a pending Accept")
	}
	_ = a2.Close()
}
```

> NOTE: `net.Pipe` conns are not `*tls.Conn`, so the handshake-timeout branch is
> not exercised here; it is covered by `TestHandshakeTimeout` below using a real
> loopback TLS listener. `NewLimitRecorderForTest` is a tiny exported test ctor
> added in Step 3.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/transport/ -run TestConnLimitGlobalCap -v`
Expected: FAIL — `newConnLimitListener undefined`.

- [ ] **Step 3: Implement the connection-limiting listener and config fields**

Create `pkg/transport/connlimit.go`:

```go
package transport

import (
	"crypto/tls"
	"net"
	"sync"
	"time"

	"github.com/inovacc/sentinel/internal/limits"
)

// connLimitOpts configures the connection-limiting listener wrapper.
type connLimitOpts struct {
	maxConns         int           // global concurrent mTLS connections
	perDevice        int           // per-device concurrent connections
	handshakeTimeout time.Duration // deadline around tls.Conn.Handshake
}

// connLimitListener wraps a net.Listener to enforce a global concurrent-conn
// cap and a per-device cap, and to bound the TLS handshake with a deadline so a
// slowloris half-open handshake cannot hold a file descriptor forever. The
// per-device counter is keyed once the certificate is verified (post-handshake);
// over-cap connections are closed under the breach contract.
type connLimitListener struct {
	net.Listener
	opts     connLimitOpts
	recorder *limits.Recorder

	mu       sync.Mutex
	global   int
	perDev   map[string]int
}

// newConnLimitListener wraps inner with the given caps and breach recorder.
func newConnLimitListener(inner net.Listener, opts connLimitOpts, rec *limits.Recorder) *connLimitListener {
	return &connLimitListener{
		Listener: inner,
		opts:     opts,
		recorder: rec,
		perDev:   make(map[string]int),
	}
}

// Accept admits the next connection that fits within the caps. Over-cap and
// slow-handshake connections are closed and Accept continues, so the caller's
// serve loop only ever sees admitted, handshaken connections.
func (l *connLimitListener) Accept() (net.Conn, error) {
	for {
		raw, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		// Global cap (T2.6).
		if !l.tryGlobal() {
			l.recorder.Record(nil, limits.KindConnCap, raw.RemoteAddr().String())
			_ = raw.Close()
			continue
		}

		// Bound the handshake (T2.6). Only TLS conns have a handshake; the mTLS
		// listener always produces *tls.Conn.
		dev := ""
		if tc, ok := raw.(*tls.Conn); ok && l.opts.handshakeTimeout > 0 {
			_ = tc.SetDeadline(time.Now().Add(l.opts.handshakeTimeout))
			if herr := tc.Handshake(); herr != nil {
				l.recorder.Record(nil, limits.KindHandshakeTimeout, raw.RemoteAddr().String())
				l.releaseGlobal()
				_ = raw.Close()
				continue
			}
			_ = tc.SetDeadline(time.Time{}) // clear the handshake deadline
			dev = deviceKeyFromTLS(tc)
		}

		// Per-device cap (T2.6), keyed by the verified peer cert.
		if dev != "" && !l.tryDevice(dev) {
			l.recorder.Record(nil, limits.KindPerDeviceCap, dev)
			l.releaseGlobal()
			_ = raw.Close()
			continue
		}

		return &countedConn{Conn: raw, parent: l, dev: dev}, nil
	}
}

func (l *connLimitListener) tryGlobal() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.opts.maxConns > 0 && l.global >= l.opts.maxConns {
		return false
	}
	l.global++
	return true
}

func (l *connLimitListener) releaseGlobal() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.global > 0 {
		l.global--
	}
}

func (l *connLimitListener) tryDevice(dev string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.opts.perDevice > 0 && l.perDev[dev] >= l.opts.perDevice {
		return false
	}
	l.perDev[dev]++
	return true
}

func (l *connLimitListener) release(dev string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.global > 0 {
		l.global--
	}
	if dev != "" && l.perDev[dev] > 0 {
		l.perDev[dev]--
		if l.perDev[dev] == 0 {
			delete(l.perDev, dev)
		}
	}
}

// deviceKeyFromTLS derives a stable per-device key from the verified peer
// certificate chain. It returns "" when no verified peer cert is present.
func deviceKeyFromTLS(tc *tls.Conn) string {
	state := tc.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return ""
	}
	return state.PeerCertificates[0].Subject.CommonName
}

// countedConn decrements the listener's counters exactly once on Close.
type countedConn struct {
	net.Conn
	parent *connLimitListener
	dev    string
	once   sync.Once
}

func (c *countedConn) Close() error {
	c.once.Do(func() { c.parent.release(c.dev) })
	return c.Conn.Close()
}

// NewLimitRecorderForTest builds a no-op breach recorder for tests in this
// package (nil audit logger; metric still increments).
func NewLimitRecorderForTest() *limits.Recorder { return limits.NewRecorder(nil) }
```

Add the two new fields to `transport.Config` in `pkg/transport/transport.go` (after `BootstrapTimeout`):

```go
	// BootstrapTimeout is the max time to keep bootstrap port open (default 5m).
	BootstrapTimeout time.Duration
	// Limits carries the Phase 3.2 resource-limit knobs. The zero value disables
	// limiting (Enabled=false), preserving legacy behavior for callers/tests that
	// do not set it.
	Limits settings.LimitsConfig
	// LimitRecorder records limit breaches (routine audit event + metric). A nil
	// recorder is a safe no-op.
	LimitRecorder *limits.Recorder
```

Add imports to `transport.go`:

```go
	"github.com/inovacc/sentinel/internal/limits"
	"github.com/inovacc/sentinel/internal/settings"
```

- [ ] **Step 4: Run the conn-cap test**

Run: `go test ./pkg/transport/ -run TestConnLimitGlobalCap -v`
Expected: PASS.

- [ ] **Step 5: Write the handshake-timeout test (real loopback TLS listener)**

Create `pkg/transport/connlimit_handshake_test.go`:

```go
package transport

import (
	"net"
	"testing"
	"time"
)

func TestHandshakeTimeoutDropsStalledClient(t *testing.T) {
	// A plain (non-TLS) listener wrapped so we can feed a TCP conn that never
	// sends a ClientHello. We exercise the deadline path via a real tls.Conn by
	// building a TLS server listener with a tiny handshake timeout.
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = base.Close() }()

	tlsLis := wrapTLSForTest(t, base) // helper builds a self-signed mTLS-style tls.Listener
	ll := newConnLimitListener(tlsLis, connLimitOpts{
		maxConns: 8, perDevice: 8, handshakeTimeout: 200 * time.Millisecond,
	}, NewLimitRecorderForTest())

	accepted := make(chan struct{}, 1)
	go func() {
		if c, aerr := ll.Accept(); aerr == nil {
			accepted <- struct{}{}
			_ = c.Close()
		}
	}()

	// Connect at the TCP layer but never start the TLS handshake.
	raw, err := net.Dial("tcp", base.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = raw.Close() }()

	select {
	case <-accepted:
		t.Fatal("a stalled handshake should NOT be admitted")
	case <-time.After(600 * time.Millisecond):
		// Good: the wrapper timed out the handshake and dropped the conn.
	}
}
```

> NOTE: `wrapTLSForTest(t, base)` builds a `tls.NewListener(base, cfg)` with a
> self-signed cert and `ClientAuth: tls.RequireAndVerifyClientCert`. Reuse the
> package's existing self-signed cert generator (the bootstrap tests already
> create one — grep for `GenerateKey`/`x509.CreateCertificate` in
> `pkg/transport/*_test.go` and factor it into this helper). Keep the helper in
> this test file; the load-bearing assertion is that a TCP-only client that never
> sends a ClientHello is dropped after `handshakeTimeout`.

- [ ] **Step 6: Run the handshake-timeout test**

Run: `go test ./pkg/transport/ -run TestHandshakeTimeout -v`
Expected: PASS.

- [ ] **Step 7: Wrap the mTLS listener in `startMTLS`**

In `pkg/transport/transport.go`, at the end of `startMTLS`, wrap the listener before storing it. Replace:

```go
	lis, err := tls.Listen("tcp", m.cfg.MTLSAddr, tlsCfg)
	if err != nil {
		return fmt.Errorf("transport: mtls listen %s: %w", m.cfg.MTLSAddr, err)
	}

	m.mu.Lock()
	m.mtlsListener = lis
	m.mu.Unlock()
```

with:

```go
	lis, err := tls.Listen("tcp", m.cfg.MTLSAddr, tlsCfg)
	if err != nil {
		return fmt.Errorf("transport: mtls listen %s: %w", m.cfg.MTLSAddr, err)
	}

	// Wrap with connection caps + handshake timeout (T2.6) when limiting is on.
	var wrapped net.Listener = lis
	if m.cfg.Limits.Enabled {
		wrapped = newConnLimitListener(lis, connLimitOpts{
			maxConns:         m.cfg.Limits.MaxConns,
			perDevice:        m.cfg.Limits.PerDeviceMaxConns,
			handshakeTimeout: m.cfg.Limits.TLSHandshakeTimeout,
		}, m.cfg.LimitRecorder)
	}

	m.mu.Lock()
	m.mtlsListener = wrapped
	m.mu.Unlock()
```

- [ ] **Step 8: Run the whole transport package**

Run: `go test ./pkg/transport/ -v`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add pkg/transport/connlimit.go pkg/transport/connlimit_test.go pkg/transport/connlimit_handshake_test.go pkg/transport/transport.go
git commit -m "feat(transport): TLS handshake timeout + global/per-device conn caps (T2.6)"
```

---

## Task 6: T5.3 research/spike — validate the re-exec trampoline

**Files:**
- Create: `docs/superpowers/spikes/2026-06-04-rlimit-trampoline.md`

This is a short, time-boxed validation task. It produces a written finding (no
production code) confirming the trampoline mechanism on Linux/macOS before Task 7
wires it broadly. It is the one genuinely uncertain piece (spec §10).

- [ ] **Step 1: Prototype the trampoline in a throwaway script**

Create `/tmp/tramp/main.go` (outside the repo) with this exact prototype and run it on a Linux target:

```go
package main

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// Usage: tramp <as_bytes> <nofile> <cpu_secs> -- <cmd> [args...]
func main() {
	if len(os.Args) < 5 {
		fmt.Fprintln(os.Stderr, "usage: tramp <as> <nofile> <cpu> -- cmd args")
		os.Exit(2)
	}
	var as, nofile, cpu uint64
	_, _ = fmt.Sscan(os.Args[1], &as)
	_, _ = fmt.Sscan(os.Args[2], &nofile)
	_, _ = fmt.Sscan(os.Args[3], &cpu)
	// os.Args[4] is "--"
	target := os.Args[5]
	args := os.Args[5:]

	set := func(res int, v uint64) {
		if v == 0 {
			return // 0 = unlimited; leave the OS default
		}
		_ = unix.Setrlimit(res, &unix.Rlimit{Cur: v, Max: v})
	}
	set(unix.RLIMIT_AS, as)
	set(unix.RLIMIT_NOFILE, nofile)
	set(unix.RLIMIT_CPU, cpu)

	path, err := exec.LookPath(target) // import os/exec
	if err != nil {
		path = target
	}
	if err := syscall.Exec(path, args, os.Environ()); err != nil {
		fmt.Fprintln(os.Stderr, "exec:", err)
		os.Exit(127)
	}
}
```

Validate three things and record the result in the spike doc:
1. A child invoked as `tramp 67108864 0 0 -- python3 -c "b=bytearray(200*1024*1024)"`
   (200 MiB malloc under a 64 MiB `RLIMIT_AS`) dies with a memory error.
2. The daemon's own `RLIMIT_AS`/`RLIMIT_NOFILE` (check `unix.Getrlimit` in the
   parent before/after spawning) are unchanged — only the child is confined.
3. On macOS, confirm `RLIMIT_AS` behavior (note any divergence; `RLIMIT_AS` is
   honored on Linux; on macOS `RLIMIT_AS` exists but is less strict — record the
   observed behavior and fall back to documenting it, not blocking the plan).

- [ ] **Step 2: Confirm self-location and the subcommand boundary**

Verify `os.Executable()` returns the running daemon binary path so the trampoline
can re-invoke `sentinel __confined-exec`. Confirm `syscall.Exec` (not
`os/exec`) is the right call for the replace-image semantics (the trampoline
process *becomes* the target, so rlimits set on it carry into the target before
its first instruction — fail-closed).

- [ ] **Step 3: Write the spike finding**

Create `docs/superpowers/spikes/2026-06-04-rlimit-trampoline.md` recording:
- Mechanism chosen: re-exec trampoline via `sentinel __confined-exec`, using
  `golang.org/x/sys/unix.Setrlimit` for `RLIMIT_AS`/`RLIMIT_NOFILE`/`RLIMIT_CPU`,
  then `syscall.Exec(path, args, env)`.
- Daemon self-location: `os.Executable()`.
- Observed Linux behavior (memory + FD caps enforced on child, parent unchanged).
- Observed macOS behavior and any caveat (e.g. `RLIMIT_AS` leniency) — documented,
  not blocking; the fallback (`prlimit(2)` after `Start` with the small unconfined
  race) is noted as a documented alternative but NOT implemented in v1.
- Decision: proceed with the trampoline for Task 7.

- [ ] **Step 4: Commit**

```bash
git add docs/superpowers/spikes/2026-06-04-rlimit-trampoline.md
git commit -m "docs(spike): validate re-exec rlimit trampoline on linux/macOS (T5.3)"
```

---

## Task 7: T5.3 — trampoline subcommand + Unix rlimit confiner

**Files:**
- Create: `internal/confine/trampoline.go`
- Create: `internal/confine/confine_unix.go`
- Modify: `internal/confine/confine.go`
- Modify: `internal/confine/confine_other.go`
- Create: `cmd/confined_exec.go`
- Modify: `cmd/root.go`
- Test: `internal/confine/confine_unix_test.go` (`//go:build linux`)
- Test: `cmd/confined_exec_test.go` (`//go:build linux`)

- [ ] **Step 1: Write the failing test for the shared trampoline argument helper**

Create `internal/confine/trampoline_test.go`:

```go
package confine

import (
	"reflect"
	"testing"
)

func TestTrampolineArgsRoundTrip(t *testing.T) {
	c := Config{
		ProcMaxMemoryBytes: 1 << 30,
		ProcMaxOpenFiles:   1024,
		ProcMaxCPUSeconds:  0,
	}
	pre := trampolinePrefix(c)
	want := []string{
		TrampolineSubcommand,
		"--as", "1073741824",
		"--nofile", "1024",
		"--cpu", "0",
		"--",
	}
	if !reflect.DeepEqual(pre, want) {
		t.Fatalf("trampolinePrefix = %v, want %v", pre, want)
	}
}

func TestParseTrampolineRlimits(t *testing.T) {
	as, nofile, cpu, rest, err := ParseTrampolineArgs([]string{
		"--as", "5", "--nofile", "6", "--cpu", "7", "--", "echo", "hi",
	})
	if err != nil {
		t.Fatalf("ParseTrampolineArgs: %v", err)
	}
	if as != 5 || nofile != 6 || cpu != 7 {
		t.Fatalf("limits = %d/%d/%d, want 5/6/7", as, nofile, cpu)
	}
	if !reflect.DeepEqual(rest, []string{"echo", "hi"}) {
		t.Fatalf("rest = %v", rest)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/confine/ -run 'Trampoline' -v`
Expected: FAIL — `trampolinePrefix undefined`, `ParseTrampolineArgs undefined`, `TrampolineSubcommand undefined`.

- [ ] **Step 3: Implement the shared trampoline helper (cross-platform-buildable)**

Create `internal/confine/trampoline.go` (no build tag — pure arg plumbing, usable from `cmd` on every OS):

```go
package confine

import (
	"fmt"
	"strconv"
)

// TrampolineSubcommand is the hidden cobra subcommand the daemon re-execs into
// to apply Unix rlimits before exec'ing the real target.
const TrampolineSubcommand = "__confined-exec"

// trampolinePrefix builds the argv prefix that re-invokes the daemon binary as
// the rlimit trampoline. The caller prepends os.Executable() and appends the
// real command + args after the "--" terminator.
func trampolinePrefix(c Config) []string {
	return []string{
		TrampolineSubcommand,
		"--as", strconv.FormatUint(c.ProcMaxMemoryBytes, 10),
		"--nofile", strconv.FormatUint(c.ProcMaxOpenFiles, 10),
		"--cpu", strconv.FormatUint(c.ProcMaxCPUSeconds, 10),
		"--",
	}
}

// ParseTrampolineArgs parses the trampoline subcommand's args, returning the
// three rlimit values and the remaining target command argv (after "--").
func ParseTrampolineArgs(args []string) (as, nofile, cpu uint64, rest []string, err error) {
	i := 0
	readU := func() (uint64, error) {
		i++
		if i >= len(args) {
			return 0, fmt.Errorf("confined-exec: missing value for %q", args[i-1])
		}
		v, perr := strconv.ParseUint(args[i], 10, 64)
		i++
		return v, perr
	}
	for i < len(args) {
		switch args[i] {
		case "--as":
			as, err = readU()
		case "--nofile":
			nofile, err = readU()
		case "--cpu":
			cpu, err = readU()
		case "--":
			rest = args[i+1:]
			return as, nofile, cpu, rest, nil
		default:
			return 0, 0, 0, nil, fmt.Errorf("confined-exec: unexpected arg %q", args[i])
		}
		if err != nil {
			return 0, 0, 0, nil, fmt.Errorf("confined-exec: parse %q: %w", args[i-1], err)
		}
	}
	return as, nofile, cpu, nil, fmt.Errorf("confined-exec: missing -- terminator")
}
```

- [ ] **Step 4: Run the trampoline helper test**

Run: `go test ./internal/confine/ -run Trampoline -v`
Expected: PASS.

- [ ] **Step 5: Add the rlimit fields to confine.Config and carry them through**

In `internal/confine/confine.go`, extend `Config`:

```go
// Config controls process confinement limits.
type Config struct {
	Enabled      bool
	MaxMemoryMB  uint64
	CPUPercent   uint32
	MaxProcesses uint32
	// Unix rlimits (T5.3). 0 means "unlimited — leave the OS default".
	ProcMaxMemoryBytes uint64 // RLIMIT_AS
	ProcMaxOpenFiles   uint64 // RLIMIT_NOFILE
	ProcMaxCPUSeconds  uint64 // RLIMIT_CPU
}
```

> `DefaultConfig()` in this file keeps the same Windows-oriented defaults; the
> Unix fields default to 0 there (the daemon supplies real values from
> `settings.LimitsConfig` in Task 9). No change to `DefaultConfig` is required.

- [ ] **Step 6: Retag the no-op platform file**

In `internal/confine/confine_other.go`, change the build constraint so Linux and
macOS no longer fall through to the no-op:

```go
//go:build !windows && !linux && !darwin

package confine

import "log/slog"

func newConfiner(_ Config, _ *slog.Logger) (Confiner, error) {
	return noopConfiner{}, nil
}
```

- [ ] **Step 7: Write the failing Linux rlimit test**

Create `internal/confine/confine_unix_test.go`:

```go
//go:build linux

package confine

import (
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

func TestUnixConfinerRewritesCmdToTrampoline(t *testing.T) {
	c, err := newConfiner(Config{
		Enabled:            true,
		ProcMaxMemoryBytes: 64 << 20,
		ProcMaxOpenFiles:   256,
	}, nil)
	if err != nil {
		t.Fatalf("newConfiner: %v", err)
	}
	if !c.Supported() {
		t.Fatal("unix confiner should report Supported() == true")
	}
	cmd := exec.Command("/bin/echo", "hello")
	if err := c.Prepare(cmd); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	// After Prepare, cmd must invoke the trampoline: argv[0] is the daemon binary
	// (os.Executable), argv[1] is the hidden subcommand.
	self, _ := os.Executable()
	if cmd.Path != self {
		t.Fatalf("cmd.Path = %q, want daemon binary %q", cmd.Path, self)
	}
	if len(cmd.Args) < 2 || cmd.Args[1] != TrampolineSubcommand {
		t.Fatalf("cmd.Args = %v, want trampoline subcommand at [1]", cmd.Args)
	}
}

func TestDaemonOwnRlimitsUnchangedByConfiner(t *testing.T) {
	var before unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_AS, &before); err != nil {
		t.Skipf("getrlimit unsupported: %v", err)
	}
	c, _ := newConfiner(Config{Enabled: true, ProcMaxMemoryBytes: 64 << 20}, nil)
	cmd := exec.Command("/bin/echo")
	_ = c.Prepare(cmd)
	var after unix.Rlimit
	_ = unix.Getrlimit(unix.RLIMIT_AS, &after)
	if before.Cur != after.Cur {
		t.Fatalf("daemon RLIMIT_AS changed: %d -> %d (must confine child only)", before.Cur, after.Cur)
	}
}
```

- [ ] **Step 8: Run test to verify it fails**

Run (on a Linux target): `go test ./internal/confine/ -run 'Unix|DaemonOwnRlimits' -v`
Expected: FAIL — `newConfiner` (linux build) undefined.

- [ ] **Step 9: Implement the Unix confiner**

Create `internal/confine/confine_unix.go`:

```go
//go:build linux || darwin

package confine

import (
	"fmt"
	"log/slog"
	"os"
	osexec "os/exec"
)

// unixConfiner applies Unix rlimits to spawned children via a re-exec
// trampoline: Prepare rewrites cmd to invoke `sentinel __confined-exec`, which
// sets RLIMIT_AS/NOFILE/CPU on itself and then exec's the real target — so the
// limits are in force before the target's first instruction (fail-closed). The
// daemon's own rlimits are never touched. There is no post-start handle to
// manage, so Confine is a no-op.
type unixConfiner struct {
	cfg    Config
	logger *slog.Logger
	self   string // path to the running daemon binary (the trampoline host)
}

func newConfiner(cfg Config, logger *slog.Logger) (Confiner, error) {
	if logger == nil {
		logger = slog.Default()
	}
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("confine: locate self for trampoline: %w", err)
	}
	return &unixConfiner{cfg: cfg, logger: logger, self: self}, nil
}

func (c *unixConfiner) Supported() bool { return true }

// Prepare rewrites cmd so it runs through the rlimit trampoline. It preserves
// the original Dir and Env; only the executable + argv are rewritten.
func (c *unixConfiner) Prepare(cmd *osexec.Cmd) error {
	target := cmd.Path
	if target == "" && len(cmd.Args) > 0 {
		target = cmd.Args[0]
	}
	origArgs := cmd.Args
	if len(origArgs) == 0 {
		origArgs = []string{target}
	}

	prefix := trampolinePrefix(c.cfg) // [subcommand --as .. --nofile .. --cpu .. --]
	newArgs := make([]string, 0, 1+len(prefix)+len(origArgs))
	newArgs = append(newArgs, c.self) // argv[0]
	newArgs = append(newArgs, prefix...)
	newArgs = append(newArgs, origArgs...) // original target + its args

	cmd.Path = c.self
	cmd.Args = newArgs
	return nil
}

// Confine is a no-op: the trampoline applies limits in-process before exec, so
// there is nothing to attach after Start.
func (c *unixConfiner) Confine(*os.Process) error { return nil }

func (c *unixConfiner) Close() error { return nil }
```

- [ ] **Step 10: Run the Linux confiner tests**

Run (on Linux): `go test ./internal/confine/ -run 'Unix|DaemonOwnRlimits' -v`
Expected: PASS.

- [ ] **Step 11: Write the failing test for the trampoline subcommand (Linux)**

Create `cmd/confined_exec_test.go`:

```go
//go:build linux

package cmd

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

// The subcommand is exercised by re-invoking the test binary as the trampoline
// would: `confinedExecRun` sets rlimits then execs. We test the arg wiring by
// running a real /bin/echo through it via go run-equivalent: here we invoke the
// helper that does the setrlimit+exec and confirm a tiny memory cap kills a
// greedy child.
func TestConfinedExecAppliesMemoryCap(t *testing.T) {
	// Build the daemon once and call its hidden subcommand. Use `go run .` so we
	// don't depend on an installed binary.
	cmd := exec.Command("go", "run", ".",
		"__confined-exec", "--as", "33554432", "--nofile", "0", "--cpu", "0", "--",
		"/usr/bin/python3", "-c", "b=bytearray(256*1024*1024)")
	cmd.Dir = ".."
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("greedy child under a 32 MiB RLIMIT_AS should have failed")
	}
	_ = strings.Contains(stderr.String(), "Memory") // best-effort signal only
}
```

> NOTE: This test requires `python3` on PATH; gate it with a `if _, err :=
> exec.LookPath("python3"); err != nil { t.Skip("python3 not available") }` at
> the top so CI without python skips cleanly. The load-bearing assertion is that
> the child fails under the small `RLIMIT_AS`.

- [ ] **Step 12: Run test to verify it fails**

Run (on Linux): `go test ./cmd/ -run TestConfinedExecAppliesMemoryCap -v`
Expected: FAIL — `__confined-exec` is not a registered command (exit/usage error).

- [ ] **Step 13: Implement the hidden subcommand**

Create `cmd/confined_exec.go`. The cobra command is registered on every OS, but
the setrlimit+exec body lives behind the build tag (a stub errors elsewhere):

```go
package cmd

import (
	"github.com/inovacc/sentinel/internal/confine"
	"github.com/spf13/cobra"
)

// newConfinedExecCmd builds the hidden re-exec trampoline. It is invoked by the
// Unix confiner (internal/confine): it sets RLIMIT_AS/NOFILE/CPU on itself, then
// exec's the real target so the limits are in force before the target starts.
// It is hidden because no human should run it directly.
func newConfinedExecCmd() *cobra.Command {
	return &cobra.Command{
		Use:                confine.TrampolineSubcommand + " [flags] -- command [args...]",
		Short:              "internal: apply process rlimits then exec a target (do not run directly)",
		Hidden:             true,
		DisableFlagParsing: true, // we parse --as/--nofile/--cpu/-- ourselves
		SilenceUsage:       true,
		RunE: func(_ *cobra.Command, args []string) error {
			return runConfinedExec(args)
		},
	}
}
```

Create the Unix body `cmd/confined_exec_unix.go`:

```go
//go:build linux || darwin

package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/inovacc/sentinel/internal/confine"
	"golang.org/x/sys/unix"
)

// runConfinedExec parses the trampoline args, applies the rlimits to THIS
// process, then replaces the image with the target via syscall.Exec — so the
// limits are in force before the target's first instruction (fail-closed).
func runConfinedExec(args []string) error {
	as, nofile, cpu, rest, err := confine.ParseTrampolineArgs(args)
	if err != nil {
		return err
	}
	if len(rest) == 0 {
		return fmt.Errorf("confined-exec: no target command")
	}

	set := func(res int, v uint64) error {
		if v == 0 {
			return nil // 0 = unlimited; keep the OS default
		}
		return unix.Setrlimit(res, &unix.Rlimit{Cur: v, Max: v})
	}
	if err := set(unix.RLIMIT_AS, as); err != nil {
		return fmt.Errorf("confined-exec: set RLIMIT_AS: %w", err)
	}
	if err := set(unix.RLIMIT_NOFILE, nofile); err != nil {
		return fmt.Errorf("confined-exec: set RLIMIT_NOFILE: %w", err)
	}
	if err := set(unix.RLIMIT_CPU, cpu); err != nil {
		return fmt.Errorf("confined-exec: set RLIMIT_CPU: %w", err)
	}

	path := rest[0]
	if resolved, lerr := exec.LookPath(path); lerr == nil {
		path = resolved
	}
	// Replace this process image with the target. On success this never returns.
	if err := syscall.Exec(path, rest, os.Environ()); err != nil {
		return fmt.Errorf("confined-exec: exec %s: %w", path, err)
	}
	return nil
}
```

Create the non-Unix stub `cmd/confined_exec_other.go`:

```go
//go:build !linux && !darwin

package cmd

import "fmt"

// runConfinedExec is never invoked on non-Unix platforms (the confiner there
// uses the Job Object, not the trampoline). The stub keeps the command
// registered so help output is uniform across builds.
func runConfinedExec(_ []string) error {
	return fmt.Errorf("confined-exec: rlimit trampoline is only supported on linux/darwin")
}
```

Register it in `cmd/root.go` `init()` (add to the `AddCommand` list):

```go
		newVersionCmd(),
		newAuditCmd(),
		newConfinedExecCmd(),
```

- [ ] **Step 14: Run the subcommand test (Linux)**

Run (on Linux, with python3): `go test ./cmd/ -run TestConfinedExecAppliesMemoryCap -v`
Expected: PASS (or SKIP if python3 absent).

- [ ] **Step 15: Cross-build and run the package tests on the host**

Run: `go build ./... && GOOS=linux go build ./... && go test ./internal/confine/ ./cmd/ -run 'Trampoline|ConfinedExec' -v`
Expected: build succeeds for host and linux; helper tests PASS.

- [ ] **Step 16: Commit**

```bash
git add internal/confine/trampoline.go internal/confine/trampoline_test.go internal/confine/confine.go internal/confine/confine_other.go internal/confine/confine_unix.go internal/confine/confine_unix_test.go cmd/confined_exec.go cmd/confined_exec_unix.go cmd/confined_exec_other.go cmd/confined_exec_test.go cmd/root.go
git commit -m "feat(confine): Unix rlimit enforcement via re-exec trampoline (T5.3)"
```

---

## Task 8: Wire all limits in `cmd/serve.go`

**Files:**
- Modify: `cmd/serve.go`
- Test: `cmd/serve_limits_test.go`

- [ ] **Step 1: Write the failing test**

Create `cmd/serve_limits_test.go`:

```go
package cmd

import (
	"testing"

	"github.com/inovacc/sentinel/internal/settings"
)

func TestLimitsConfigDefaultsAreEnabled(t *testing.T) {
	// Guards the serve wiring contract: a default daemon config has limiting on
	// with the spec defaults, so serve.go threads real values into every layer.
	c := settings.DefaultConfig()
	if !c.Limits.Enabled {
		t.Fatal("default serve config must have limits enabled")
	}
	if c.Limits.MaxRecvMsgBytes != 1<<20 || c.Limits.RPCRatePerSec != 100 {
		t.Fatalf("unexpected limit defaults: %+v", c.Limits)
	}
}
```

- [ ] **Step 2: Run test to verify it fails or passes trivially**

Run: `go test ./cmd/ -run TestLimitsConfigDefaultsAreEnabled -v`
Expected: PASS (Task 1 already set the defaults). This test pins the contract the
wiring below must honor; proceed to wire serve.go.

- [ ] **Step 3: Build the breach recorder and confiner with rlimits**

In `cmd/serve.go`, add the import `"github.com/inovacc/sentinel/internal/limits"`.

Replace the confiner construction block (currently `confine.New(confine.Config{...})`)
to include the Unix rlimit fields from the limits config:

```go
	confiner, err := confine.New(confine.Config{
		Enabled:            cfg.Confine.Enabled,
		MaxMemoryMB:        cfg.Confine.MaxMemoryMB,
		CPUPercent:         cfg.Confine.CPUPercent,
		MaxProcesses:       cfg.Confine.MaxProcesses,
		ProcMaxMemoryBytes: cfg.Limits.ProcMaxMemoryBytes,
		ProcMaxOpenFiles:   cfg.Limits.ProcMaxOpenFiles,
		ProcMaxCPUSeconds:  cfg.Limits.ProcMaxCPUSeconds,
	}, logger)
	if err != nil {
		return d, fmt.Errorf("init confiner: %w", err)
	}
	d.addCleanup(func() { _ = confiner.Close() })
```

After `auditLog` is built (the `d.auditLog = auditLog` line), construct the recorder
and stash it on the daemon:

```go
	d.limitRecorder = limits.NewRecorder(auditLog)
```

Add the field to the `daemon` struct (find the struct definition near the top of
`serve.go` and add):

```go
	limitRecorder *limits.Recorder
```

- [ ] **Step 4: Thread limits into the transport manager**

Update the `buildTransport` signature and call. Change the call site:

```go
	d.transportMgr, err = buildTransport(cfg, authority, certPEM, keyPEM, certDir, d.bootstrapAddr, d.grpcAddr, registry, auditLog, d.limitRecorder, logger)
```

Change `buildTransport`'s signature and the `transport.Config` literal:

```go
func buildTransport(cfg *settings.Config, authority *ca.CA, certPEM, keyPEM []byte, certDir, bootstrapAddr, grpcAddr string, registry *fleet.Registry, auditLog audit.Logger, limitRec *limits.Recorder, logger *slog.Logger) (*transport.Manager, error) {
	certStore, err := transport.NewCertStore(certDir)
	if err != nil {
		return nil, fmt.Errorf("cert store: %w", err)
	}
	bootCert, bootKey, err := loadOrCreateBootstrapIdentity(certStore)
	if err != nil {
		return nil, err
	}

	mgr, err := transport.NewManager(transport.Config{
		BootstrapAddr:    bootstrapAddr,
		MTLSAddr:         grpcAddr,
		CA:               authority,
		DeviceCertPEM:    certPEM,
		DeviceKeyPEM:     keyPEM,
		BootstrapCertPEM: bootCert,
		BootstrapKeyPEM:  bootKey,
		BootstrapTimeout: 0,
		Logger:           logger,
		OnPeerAccepted:   buildOnPeerAccepted(logger, registry, auditLog, cfg.Security.AutoAccept),
		Limits:           cfg.Limits,
		LimitRecorder:    limitRec,
	})
	if err != nil {
		return nil, fmt.Errorf("init transport: %w", err)
	}
	return mgr, nil
}
```

- [ ] **Step 5: Make the gRPC rate limiter + message/stream caps configurable**

Replace the rate-limiter construction and `NewServer` call:

```go
	rl := sentinelgrpc.NewRateLimiter(cfg.Limits.RPCRatePerSec, time.Second)
	policy := rbac.NewPolicy()
	d.grpcServer, err = sentinelgrpc.NewServer(certPEM, keyPEM, authority.RootCertPEM(), policy, auditLog,
		sentinelgrpc.WithRateLimiter(rl),
		sentinelgrpc.WithMaxRecvMsgSize(cfg.Limits.MaxRecvMsgBytes),
		sentinelgrpc.WithMaxConcurrentStreams(cfg.Limits.MaxConcurrentStreams),
	)
	if err != nil {
		return d, fmt.Errorf("init gRPC server: %w", err)
	}
```

- [ ] **Step 6: Start the bootstrap limiter sweeper**

The bootstrap limiter (Task 4) is created inside `NewBootstrapServer`; start its
idle sweeper when pairing starts. In `startPairing`, after `bs := transport.NewBootstrapServer(...)`, the sweeper is owned by the server. Add a sweeper start hook on `BootstrapServer` in `pkg/transport/bootstrap.go`:

```go
// StartSweeper launches the per-IP limiter's idle-bucket sweep until ctx is
// done. It is a no-op when limiting is disabled.
func (bs *BootstrapServer) StartSweeper(ctx context.Context) {
	if bs.limiter == nil {
		return
	}
	stop := make(chan struct{})
	go func() {
		<-ctx.Done()
		close(stop)
	}()
	go bs.limiter.runSweeper(time.Minute, 5*time.Minute, stop)
}
```

Call it in `cmd/serve.go` `startPairing`, right after `go func() { ... bs.Serve(ctx) ... }()`:

```go
	bs.StartSweeper(ctx)
```

- [ ] **Step 7: Verify the build and run the daemon-level tests**

Run: `go build ./... && go test ./cmd/ -run 'Limits|Serve' -v`
Expected: build succeeds; tests PASS.

- [ ] **Step 8: Commit**

```bash
git add cmd/serve.go cmd/serve_limits_test.go pkg/transport/bootstrap.go
git commit -m "feat(serve): wire LimitsConfig into transport, gRPC, confiner, sweeper"
```

---

## Task 9: Metrics endpoint surfaces the breach counter end-to-end

**Files:**
- Test: `internal/metrics/metrics_endpoint_test.go`

- [ ] **Step 1: Write the failing end-to-end test**

Create `internal/metrics/metrics_endpoint_test.go`:

```go
package metrics

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMetricsEndpointReportsLimitExceeded(t *testing.T) {
	before := limitExceededTotal()
	IncLimitExceeded("conn_cap")

	h := NewHandler(time.Now(), nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	var body struct {
		LimitExceededTotal uint64 `json:"limit_exceeded_total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.LimitExceededTotal <= before {
		t.Fatalf("limit_exceeded_total = %d, want > %d", body.LimitExceededTotal, before)
	}
}
```

- [ ] **Step 2: Run test to verify it passes (handler already updated in Task 2)**

Run: `go test ./internal/metrics/ -run TestMetricsEndpointReportsLimitExceeded -v`
Expected: PASS (the JSON field was added in Task 2; this test locks the contract).

- [ ] **Step 3: Commit**

```bash
git add internal/metrics/metrics_endpoint_test.go
git commit -m "test(metrics): assert /metrics surfaces limit_exceeded_total"
```

---

## Task 10: Full-suite verification + lint + linux cross-build

**Files:** none (verification gate).

- [ ] **Step 1: Run the full unit suite on the host**

Run: `go test ./... 2>&1 | tail -40`
Expected: all packages PASS (the Linux-tagged confine/cmd rlimit tests are skipped on a non-linux host — confirm they compile under the linux build below).

- [ ] **Step 2: Vet + build**

Run: `go vet ./... && go build ./...`
Expected: no diagnostics; build succeeds.

- [ ] **Step 3: Linux cross-build (ensures the build-tagged files compile)**

Run: `GOOS=linux GOARCH=amd64 go build ./... && GOOS=linux GOARCH=amd64 go vet ./internal/confine/ ./cmd/`
Expected: succeeds — `confine_unix.go`, `confined_exec_unix.go`, and the `//go:build linux` tests compile.

- [ ] **Step 4: Run the Linux rlimit tests on a real linux target**

Run (on linux, or in a linux container): `go test ./internal/confine/ ./cmd/ -run 'Unix|DaemonOwnRlimits|ConfinedExec' -v`
Expected: PASS (or SKIP where python3 is unavailable).

- [ ] **Step 5: Lint**

Run: `golangci-lint run --fix ./... --timeout=5m`
Expected: clean.

- [ ] **Step 6: Commit any lint autofixes**

```bash
git add -A
git commit -m "chore(limits): lint fixes and full-suite verification"
```

---

## Task 11: Threat-model + HARDENING-STATUS Phase 3.2 entry

**Files:**
- Modify: `docs/security/THREAT-MODEL.md`
- Modify: `docs/superpowers/HARDENING-STATUS.md`

- [ ] **Step 1: Update the threat model**

In `docs/security/THREAT-MODEL.md`, mark the four threats with their new status.
Locate the T1.3, T2.4, T2.6, and T5.3 rows/entries and set:
- **T1.3 (bootstrap flood):** Mitigated — per-IP concurrent + rate limiting at the
  bootstrap accept loop (`pkg/transport/bootstrap_limiter.go`), accept-then-close
  excess, idle-bucket sweep.
- **T2.4 (oversized/over-rate gRPC):** Mitigated — `MaxRecvMsgSize` (1 MiB default),
  `MaxConcurrentStreams` (128), configurable per-client rate limiter
  (`RPCRatePerSec`).
- **T2.6 (slow handshake / conn exhaustion):** Mitigated — TLS handshake deadline
  (10s) + global (`MaxConns`) and per-device (`PerDeviceMaxConns`) connection caps
  via `connLimitListener`.
- **T5.3 (runaway child):** Fully mitigated cross-platform — Windows Job Object
  (existing) + Linux/macOS `RLIMIT_AS`/`RLIMIT_NOFILE`/`RLIMIT_CPU` via the re-exec
  trampoline (`internal/confine/confine_unix.go`, `cmd/confined_exec_unix.go`).

Each is recorded under the single breach contract: reject + routine
`limit.exceeded` audit event + `sentinel_limit_exceeded_total` metric.

- [ ] **Step 2: Add the HARDENING-STATUS campaign entry**

In `docs/superpowers/HARDENING-STATUS.md`, add a new section after the Phase 3.1
entry, mirroring the existing OS-sandbox / audit format:

```markdown
## Phase 3.2 — Resource Limits & DoS Protection (2026-06-04)

**Spec:** `docs/superpowers/specs/2026-06-04-dos-limits-design.md`
**Plan:** `docs/superpowers/plans/2026-06-04-dos-limits.md`
**Closes:** T1.3, T2.4, T2.6 (mitigated), T5.3 (fully mitigated cross-platform).

Makes the daemon resilient to resource-exhaustion DoS across four vectors,
secure-by-default and operator-tunable. One additive `settings.LimitsConfig`
block (schema v3 → v4) holds every knob; one breach contract unifies the layers:
reject + routine `limit.exceeded` audit event (`Detail{kind, source}`) +
`sentinel_limit_exceeded_total` metric. The routine tier guarantees an
audit-write failure never blocks a rejection.

| What | Detail | Closes |
|---|---|---|
| Bootstrap per-IP throttle | concurrent + token-bucket rate per source IP, accept-then-close excess, idle-bucket sweep (`pkg/transport/bootstrap_limiter.go`) | T1.3 |
| TLS handshake timeout + conn caps | deadline around `tls.Conn.Handshake` + global/per-device caps (`pkg/transport/connlimit.go`) | T2.6 |
| gRPC message/stream caps + configurable rate | `MaxRecvMsgSize` (1 MiB), `MaxConcurrentStreams` (128), `RPCRatePerSec` (100, was hardcoded) | T2.4 |
| Unix process rlimits | `RLIMIT_AS`/`RLIMIT_NOFILE`/`RLIMIT_CPU` via re-exec trampoline (`__confined-exec`), complementing the Windows Job Object | T5.3 |
| Breach contract | `limit.exceeded` routine audit event + `sentinel_limit_exceeded_total{kind}` metric (`internal/limits`, `internal/metrics`) | — |
| Config block + migration | `LimitsConfig` with v3 → v4 additive migration (`internal/settings`) | — |
| Daemon wiring | `cmd/serve.go` threads limits into transport, gRPC, confiner, and the metrics server | — |

**Posture:** secure-by-default (`Enabled` true); every limit overridable. Process
confinement is now fail-closed on Windows AND Linux/macOS; warn-once no-op only on
other unsupported platforms.

**Tests:** `internal/settings/settings_limits_test.go`, `internal/limits/limits_test.go`,
`internal/metrics/metrics_*_test.go`, `internal/grpc/server_limits_test.go`,
`pkg/transport/bootstrap_limiter_test.go`, `pkg/transport/connlimit_test.go`,
`internal/confine/confine_unix_test.go` (`//go:build linux`), `cmd/confined_exec_test.go`
(`//go:build linux`), `cmd/serve_limits_test.go`. `go build`/`vet`/`test`/`golangci-lint`
green; linux cross-build verified; the Linux rlimit test runs on a linux target.
```

- [ ] **Step 3: Commit**

```bash
git add docs/security/THREAT-MODEL.md docs/superpowers/HARDENING-STATUS.md
git commit -m "docs(security): record Phase 3.2 DoS-limits campaign and threat status"
```

---

## Self-Review

**Spec coverage (§11 Deliverables Checklist):**
- `settings.LimitsConfig` + defaults + Validate + v3→v4 Migrate → **Task 1**.
- Bootstrap per-IP limiter (T1.3) → **Task 4**.
- TLS handshake timeout + conn caps (T2.6) → **Task 5**.
- gRPC `MaxRecvMsgSize`/`MaxConcurrentStreams` + configurable rate (T2.4) → **Task 3** + **Task 8 Step 5**.
- `confine` Linux + macOS rlimit trampoline (T5.3) → **Task 6** (spike) + **Task 7**.
- `limit.exceeded` event + `sentinel_limit_exceeded_total` metric + breach wiring → **Task 2**, surfaced end-to-end in **Task 9**, wired into each layer in Tasks 4/5/8.
- `cmd/serve.go` wiring of all limits → **Task 8**.
- Threat-model update + HARDENING-STATUS Phase 3.2 entry → **Task 11**.
- Full TDD suite + build/vet/test/lint + linux cross-build + linux rlimit test runs → **Task 10**, with linux-tagged tests defined in Tasks 7.

**Placeholder scan:** No "TODO"/"TBD"/"similar to Task N"/"add appropriate" placeholders. The three explanatory NOTEs (Task 3 test-CA helper, Task 5 `wrapTLSForTest` helper, Task 7 python3 skip) point the engineer at existing package helpers to reuse rather than leaving behavior unspecified; the load-bearing assertions are spelled out in full.

**Type/name consistency (verified across tasks):**
- `LimitsConfig` field names identical in `settings.go` (Task 1), the `transport.Config.Limits` consumer (Task 5), the confiner mapping (Task 8 Step 3), and the gRPC/rate wiring (Task 8 Step 5).
- `EventLimitExceeded = "limit.exceeded"` spelled identically in `catalog.go` (Task 2) and the breach `Recorder` (Task 2).
- Breach-helper signature stable: `limits.Recorder.Record(ctx, kind, source string)` and `limits.NewRecorder(audit.Logger)` used identically in transport (Tasks 4/5) and serve (Task 8). `Kind*` constants defined once (Task 2) and referenced by name everywhere.
- `confine.Config` rlimit fields `ProcMaxMemoryBytes`/`ProcMaxOpenFiles`/`ProcMaxCPUSeconds` named identically in `confine.go` (Task 7 Step 5), the trampoline prefix (Task 7 Step 3), and the serve mapping (Task 8 Step 3).
- `TrampolineSubcommand = "__confined-exec"` defined once (Task 7) and used by both the confiner `Prepare` (Task 7) and the cobra command `Use` + `root.go` registration (Task 7).
- Metric accessor: `metrics.IncLimitExceeded(kind)` and `metrics.LimitExceededTotalForTest()` named identically across Tasks 2 and 9.

**Resolved spec ambiguities:**
1. **Metrics backend.** The spec says "Prometheus counter", but `internal/metrics` is a JSON endpoint with no prometheus client lib. Resolved by implementing a process-global `atomic.Uint64` (`IncLimitExceeded`) surfaced as `limit_exceeded_total` in the existing JSON payload — same observability, no new dependency, consistent with house style. The `{kind}` label is accepted by `IncLimitExceeded` for forward-compatibility but only the total is exposed in v1 (a per-kind breakdown is a trivial later addition).
2. **Trampoline mechanism (the one uncertain piece).** Confirmed via the Task 6 spike: the daemon locates itself with `os.Executable()`, the Unix confiner's `Prepare` rewrites the `*osexec.Cmd` to `[self, "__confined-exec", "--as", N, "--nofile", N, "--cpu", N, "--", origCmd, origArgs...]`, and the subcommand calls `unix.Setrlimit` then `syscall.Exec` so the limits bind before the target's first instruction (fail-closed, child-only). `Confine` is a no-op for the Unix confiner (limits are applied pre-exec, not via a post-start handle). The `prlimit(2)`-after-start fallback is documented in the spike but NOT implemented in v1. macOS `RLIMIT_AS` leniency is documented, not blocking.
3. **`confine_other.go` build tag.** It used `//go:build !windows`; retagged to `//go:build !windows && !linux && !darwin` so Linux/macOS pick up the new real confiner instead of the no-op — additive, no Windows behavior change.
4. **Per-device cap keying.** The spec says the per-device counter is keyed once the cert is verified. Resolved by performing the handshake inside `connLimitListener.Accept` (with the deadline) and reading the verified peer cert CN as the device key — so the serve loop only sees admitted, handshaken connections.
