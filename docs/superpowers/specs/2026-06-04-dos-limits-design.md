# Phase 3.2 — Resource Limits & DoS Protection (Design)

**Date:** 2026-06-04
**Status:** Approved (owner sign-off 2026-06-04) — ready for implementation plan
**Spec lineage:** elaborates `docs/superpowers/specs/2026-05-22-hardening-design.md` §Phase 3 workstream 3.2
**Threats closed:** T1.3, T2.4, T2.6, T5.3 — see `docs/security/THREAT-MODEL.md`

---

## 1. Goal & Non-Goals

### Goal

Make the daemon resilient to resource-exhaustion DoS across four vectors, **secure-by-default**
and operator-tunable. A peer (or unauthenticated attacker) must not be able to exhaust
connections, file descriptors, memory, or CPU by flooding the bootstrap port, holding
slow handshakes, smuggling oversized messages, or spawning a runaway child.

### Non-Goals (v1 — deferred to backlog)

- Adaptive / auto-tuning limits (load-reactive thresholds).
- Distributed / fleet-wide rate coordination (limits are per-daemon).
- cgroup v2 process isolation — `setrlimit` is the v1 Unix mechanism; cgroups are a later option.
- L7 request-cost weighting (treating expensive RPCs as worth more tokens).

---

## 2. Architecture — config-unified, layer-enforced

There is **no single god-limiter**. The four vectors act at different layers (TCP accept,
TLS handshake, gRPC interceptor, process spawn), so each layer enforces its own limit. What
unifies them is:

1. **One config block** — `settings.LimitsConfig` (schema **v3 → v4**, additive migration in
   the same style as the `audit` and `confine` blocks) holds every knob, with
   conservative-but-safe defaults. `Enabled` (default true) gates the whole subsystem.
2. **One breach contract** — when any limit is exceeded the layer **rejects** (drops the
   connection / returns `codes.ResourceExhausted` / refuses the spawn), emits a single
   **routine** audit event `limit.exceeded` with `Detail{kind, source}`, and increments a
   Prometheus counter on the existing metrics server. The audit event is **routine** on
   purpose: an audit-write failure must never block a rejection (that would make the audit
   path itself a DoS vector).

Defaults are chosen so legitimate use (chunked file transfer, normal exec bursts, a handful
of fleet peers) is never tripped; an operator tightens or loosens via the config block.

---

## 3. T1.3 — Bootstrap per-IP throttle

**Where:** the bootstrap listener accept loop (`pkg/transport/bootstrap.go`).

**What:** a per-source-IP limiter with two dimensions:
- `BootstrapPerIPMaxConns` — max *concurrent* bootstrap connections from one IP.
- `BootstrapPerIPRate` — token-bucket rate of *new* bootstrap connections/sec per IP.

Excess connections are accepted-then-immediately-closed (so the accept loop is never
blocked) and counted. Keyed by `net.IP` of the remote (not device ID — bootstrap is
pre-auth). A small periodic sweep evicts idle per-IP buckets to bound memory.

**Why a new limiter:** the existing `internal/grpc.RateLimiter` is a *post-mTLS* interceptor
keyed by device ID; it cannot see the pre-auth bootstrap handshake. T1.3 needs IP-keyed
limiting at the listener.

---

## 4. T2.6 — Handshake timeout + connection caps

**Where:** the mTLS listener/server (`pkg/transport/mtls.go`).

**What:**
- **Handshake deadline** — set a deadline around `tls.Conn.Handshake()` (default 10s) so a
  slowloris half-open handshake is dropped instead of holding a file descriptor forever.
- **Connection caps** — a connection-limiting listener wrapper enforcing global `MaxConns`
  and `PerDeviceMaxConns` (device identity is known once the cert is verified; the
  per-device counter is incremented post-handshake and decremented on close). Over-cap
  connections are closed with the breach contract (§2).

---

## 5. T2.4 — gRPC message & stream caps

**Where:** gRPC server construction (`internal/grpc/server.go`, wired in `cmd/serve.go`).

**What:**
- `grpc.MaxRecvMsgSize(MaxRecvMsgBytes)` — tightened from the 4 MB default to the configured
  cap. Chunked FS transfer (`internal/fs`) already chunks, so a tight cap (default 1 MiB)
  does not break large transfers; oversized single messages return `ResourceExhausted`.
- `grpc.MaxConcurrentStreams(MaxConcurrentStreams)` — bound concurrent streams per connection.
- **Make the existing rate limiter configurable** — replace the hardcoded
  `NewRateLimiter(100, time.Second)` in `cmd/serve.go` with `RPCRatePerSec` from the block
  (default 100). No behavior change at the default; just no longer hardcoded.

---

## 6. T5.3 — Cross-platform process rlimits

**Where:** the `internal/confine` package (extends, does not replace, the Windows Job Object).

**What:** today `confine_windows.go` enforces caps via a Job Object and `confine_other.go`
is a no-op for every non-Windows OS. Phase 3.2 adds **real Unix enforcement** for Linux and
macOS: apply `RLIMIT_AS` (address space / memory), `RLIMIT_NOFILE` (open files), and
`RLIMIT_CPU` (CPU seconds) to each spawned child, driven by `ProcMaxMemoryBytes`,
`ProcMaxOpenFiles`, and `ProcMaxCPUSeconds`.

**Mechanism (to be validated by the plan's research step):** the rlimits must apply to the
**child only**, not the daemon. Go's `os/exec` cannot set child rlimits directly via
`SysProcAttr`. The chosen mechanism is a **re-exec trampoline**: the daemon spawns a hidden
`sentinel __confined-exec` subcommand that calls `setrlimit` on itself and then `exec`s the
real target — guaranteeing the limits are in force before the target's first instruction
(fail-closed). Documented fallback if the trampoline proves problematic: `prlimit(2)` on the
child PID immediately after `Start` (with the small unconfined race noted explicitly). The
posture stays fail-closed on platforms that support confinement (Windows + Linux/macOS) and
warn-once no-op only where unsupported.

**Decide() integration:** the existing `confine.Decide`/`Supported` posture helper now reports
supported on Linux/macOS too, so `exec`/`worker` apply rlimits the same fail-closed way they
apply the Job Object on Windows.

---

## 7. Config Block

Additive `limits` block in `internal/settings`, `CurrentConfigVersion` **3 → 4**:

```go
type LimitsConfig struct {
    Enabled                bool          // default true
    // T1.3 — bootstrap (pre-auth, per source IP)
    BootstrapPerIPMaxConns int           // default 8
    BootstrapPerIPRate     int           // new conns/sec/IP; default 5
    // T2.6 — mTLS listener
    TLSHandshakeTimeout    time.Duration // default 10s
    MaxConns               int           // global concurrent mTLS conns; default 256
    PerDeviceMaxConns      int           // default 16
    // T2.4 — gRPC
    MaxRecvMsgBytes        int           // default 1 MiB (1048576)
    MaxConcurrentStreams   uint32        // default 128
    RPCRatePerSec          int           // default 100 (was hardcoded)
    // T5.3 — process rlimits (Unix; complements Windows Job Object)
    ProcMaxMemoryBytes     uint64        // RLIMIT_AS; default 1 GiB; 0 = unlimited
    ProcMaxOpenFiles       uint64        // RLIMIT_NOFILE; default 1024; 0 = unlimited
    ProcMaxCPUSeconds      uint64        // RLIMIT_CPU; default 0 (unlimited — exec already has a wall-clock timeout)
}
```

`Validate`: when `Enabled`, reject non-positive `BootstrapPerIPMaxConns`, `MaxConns`,
`PerDeviceMaxConns`, `MaxRecvMsgBytes`, `MaxConcurrentStreams`, `RPCRatePerSec`, and a
`TLSHandshakeTimeout <= 0`. The three `Proc*` caps may be 0 (meaning "unlimited", left to the
OS default). `Migrate` adds v4 defaults to configs written at version 3.

---

## 8. Audit & Metrics Integration

- **Audit:** one new catalog event `limit.exceeded` (`EventLimitExceeded`), tier **routine**,
  emitted by every layer on breach with `Detail{kind: "bootstrap_ip"|"handshake_timeout"|
  "conn_cap"|"per_device_cap"|"rpc_rate"|"msg_size"|"proc_rlimit", source: "<ip or device>"}`.
  The registry-completeness test (Phase 3.1) forces it to be classified.
- **Metrics:** a `sentinel_limit_exceeded_total{kind}` counter on the existing metrics server
  (`startMetricsServer`), so flood attempts are observable without scraping the audit log.

---

## 9. Testing Strategy (TDD)

Table-driven, red-green-refactor:

1. **Bootstrap per-IP** — open `MaxConns+1` concurrent bootstrap conns from one IP → the
   extra is closed; a second IP is unaffected; rate bucket refills over time.
2. **Handshake timeout** — a client that opens TCP but stalls the TLS handshake is dropped
   after `TLSHandshakeTimeout`; a normal handshake succeeds.
3. **Connection cap** — `MaxConns`/`PerDeviceMaxConns` reject over-cap connections and
   recover after close.
4. **gRPC message size** — a request body over `MaxRecvMsgBytes` returns
   `codes.ResourceExhausted`; one under it succeeds.
5. **Configurable RPC rate** — limiter honors `RPCRatePerSec` from config.
6. **Unix rlimit** (Linux, build-tagged) — a child that mallocs past `ProcMaxMemoryBytes`
   fails; FD cap enforced; daemon's own rlimits unchanged (trampoline isolates the child).
7. **Breach contract** — each breach emits `limit.exceeded` with the right `kind` and bumps
   the metric; audit-write failure does not block the rejection (routine tier).
8. **Migration** — a v3 config migrates to v4 with limits defaults; `Validate` rejects bad
   values.

Cross-platform: the rlimit test is `//go:build linux`; Windows keeps the Job Object path;
the connection/gRPC tests are platform-agnostic.

---

## 10. Architecture Impact & Risk

- **No new always-on goroutine storms:** the per-IP bucket map is swept on a single timer;
  the connection-limiting listener uses a counting semaphore, not a goroutine-per-conn ledger.
- **Default-tripping risk:** the biggest risk is a default that breaks a legitimate workflow
  (e.g., `MaxRecvMsgBytes` too small for a legitimate inbound RPC). Note `MaxRecvMsgSize`
  bounds *inbound request* messages only, not responses — so outbound screenshot/capture data
  is unaffected; the largest inbound messages are file-upload chunks (already chunked by
  `internal/fs`) and payload/exec requests. Mitigation: the plan verifies the largest
  legitimate inbound message and sets the default above it; every limit is overridable. We do
  **not** cap `MaxSendMsgSize`, so large outbound responses (screenshots) keep working.
- **rlimit mechanism risk:** the trampoline adds a re-exec hop per confined spawn. The plan
  **must** include a research/spike step to confirm the trampoline (vs `prlimit`-after-start)
  on Linux and macOS before wiring it broadly; this is the one genuinely uncertain piece.
- **Interaction with Phase 3.1/3.6:** `limit.exceeded` reuses the audit logger (already
  injected); the Unix rlimits slot into the existing `confine.Confiner` interface, so `exec`
  and `worker` need no new wiring — only the platform files change.

---

## 11. Deliverables Checklist

- [ ] `settings.LimitsConfig` block + defaults + `Validate` + v3→v4 `Migrate`.
- [ ] Bootstrap per-IP limiter (concurrent + rate) at the bootstrap listener (T1.3).
- [ ] TLS handshake timeout + global/per-device connection caps at the mTLS listener (T2.6).
- [ ] gRPC `MaxRecvMsgSize`/`MaxConcurrentStreams` + configurable RPC rate limiter (T2.4).
- [ ] `confine` Linux + macOS rlimit enforcement (trampoline) complementing the Job Object (T5.3).
- [ ] `limit.exceeded` audit event + `sentinel_limit_exceeded_total` metric + breach wiring.
- [ ] `cmd/serve.go` wiring of all limits from config.
- [ ] Threat-model update: T1.3/T2.4/T2.6 → mitigated, T5.3 → fully mitigated cross-platform;
      `docs/superpowers/HARDENING-STATUS.md` Phase 3.2 campaign entry.
- [ ] Full TDD suite (§9); `go build`/`vet`/`test`/`golangci-lint` green; linux cross-build;
      the Linux rlimit test actually runs on a linux target.
