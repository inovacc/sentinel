# Sentinel Threat Model

**Status:** Draft v1 (2026-05-22)
**Methodology:** STRIDE per trust boundary
**Scope:** Sentinel daemon, MCP server, supervisor, and the artifacts they own (CA, sessions DB, sandbox).
**Out of scope:** Claude Code itself, the host operating system kernel, network infrastructure below TCP, the Electron `eye/` capture app (separate process, separate threat model).

This document is the security contract for Phase 3 of `docs/superpowers/specs/2026-05-22-hardening-design.md`. Every threat row maps to a mitigation, the code that implements it, and the test that proves it.

---

## Trust Boundaries

| ID | Boundary | Outside (untrusted) | Inside (trusted) |
|----|----------|--------------------|--------------------|
| TB1 | Bootstrap port 7399 | Any host on the network | Daemon process |
| TB2 | mTLS port 7400 | Devices with valid CA-signed cert + role | Daemon process |
| TB3 | MCP stdio | Claude Code (LLM-driven; commands are attacker-controllable in adversarial scenarios) | Sentinel MCP process |
| TB4 | Supervisor IPC | Worker process (may have been compromised by exec'd command) | Monitor process |
| TB5 | Exec engine | Spawned subprocess | Daemon |
| TB6 | FS sandbox | Filesystem outside `~/.sentinel/sandbox/` | Daemon |
| TB7 | SQLite + on-disk state | Anyone with read access to the data dir | Daemon |
| TB8 | CA key store | Anyone with read access to CA key file | Daemon |
| TB9 | Auto-update channel | Anyone who can publish to the release URL or MITM HTTPS | Running daemon binary |

---

## Threats and Mitigations

Severity scale: **C**ritical / **H**igh / **M**edium / **L**ow.
Status: ✅ implemented, 🟡 partial, ❌ not yet (becomes Phase 3 work).

### TB1 — Bootstrap port 7399

| ID | STRIDE | Threat | Sev | Mitigation | Code | Test | Status |
|----|--------|--------|-----|------------|------|------|--------|
| T1.1 | S | Attacker impersonates a legitimate device during bootstrap | H | Device-ID is SHA-256 of self-signed leaf cert; operator must approve the device ID out-of-band before signing | `pkg/transport/bootstrap.go`, `internal/ca/identity.go` | `pkg/transport/bootstrap_test.go` | ✅ |
| T1.2 | T | Attacker intercepts cert-signing handshake (MITM) and substitutes their own CSR | H | Operator confirms device-ID hash on both ends before approving sign request | bootstrap CLI flow | manual UAT | 🟡 — UX-dependent; threat model documents the required operator step |
| T1.3 | D | Attacker floods bootstrap port to exhaust connections / TLS handshakes | M | Per-IP concurrent + rate limiting at the bootstrap accept loop (`pkg/transport/bootstrap_limiter.go`), accept-then-close excess, idle-bucket sweep. Breach contract: reject + routine `limit.exceeded` audit event + `sentinel_limit_exceeded_total` metric. | `pkg/transport/bootstrap_limiter.go`, `cmd/serve.go` | `pkg/transport/bootstrap_limiter_test.go` | ✅ — mitigated Phase 3.2 (2026-06-04) |
| T1.4 | E | Attacker exploits parser bug in length-prefixed JSON protocol to gain RCE in daemon | C | Strict max message size (`MaxEnvelopeSize` = 10 MiB); native Go fuzz tests on `DecodeEnvelope` | `pkg/transport/protocol.go` | `pkg/transport/protocol_fuzz_test.go` | ✅ |
| T1.5 | I | Bootstrap leaks device fingerprint info pre-auth | L | Self-signed cert only exposes device-ID, no further metadata | bootstrap protocol | bootstrap_test.go | ✅ |
| T1.6 | S/T | Peer rotates its CA (or a MITM substitutes one) so paired clients silently trust a new authority on re-pair | H | CA fingerprint pinned per peer at pairing; `connect` **refuses** to re-pair a known peer whose CA changed (unless `--force`); `doctor` probes each pinned peer and FAILs on CA-trust drift; trust failures classified into actionable re-pair guidance | `internal/ca/identity.go`, `internal/fleet/registry.go`, `cmd/connect.go`, `cmd/doctor_fleet.go`, `internal/clierr/` | `internal/ca/fingerprint_test.go`, `internal/fleet/registry_capin_test.go`, `cmd/connect_pairing_test.go`, `cmd/doctor_fleet_test.go`, `internal/clierr/clierr_test.go` | ✅ — 2026-06-03 |

### TB2 — mTLS port 7400

| ID | STRIDE | Threat | Sev | Mitigation | Code | Test | Status |
|----|--------|--------|-----|------------|------|------|--------|
| T2.1 | S | Attacker presents a self-signed or another CA's cert | C | `tls.RequireAndVerifyClientCert` + custom `ClientCAs` pool containing only our CA | `internal/grpc/server.go`, `pkg/transport/mtls.go` | `pkg/transport/mtls_test.go` | ✅ |
| T2.2 | E | Cert-holder with `reader` role calls admin-only RPCs | C | RBAC interceptor enforces minimum role per method; role extracted from X.509 custom OID | `internal/grpc/interceptor.go`, `internal/ca/role.go`, `internal/rbac/` | `internal/grpc/interceptor_test.go` | ✅ |
| T2.3 | S | Compromised cert continues to work indefinitely | H | Short-lived certs (≤30d) + CRL fetch on handshake | cert renewal (existing); CRL (Phase 3.4) | TBD | 🟡 → Phase 3.4 |
| T2.4 | T | gRPC unary request smuggles larger-than-expected payload to exhaust memory | M | `MaxRecvMsgSize` (1 MiB default), `MaxConcurrentStreams` (128), configurable per-client rate limiter (`RPCRatePerSec`). Breach contract: reject + routine `limit.exceeded` audit event + `sentinel_limit_exceeded_total` metric. | `internal/grpc/server.go`, `cmd/serve.go` | `internal/grpc/server_limits_test.go` | ✅ — mitigated Phase 3.2 (2026-06-04) |
| T2.5 | R | Privileged action happens but operator cannot prove who did it | H | Tamper-evident, actor-attributed, hash-chained security audit log; critical events fail-closed; `sentinel audit verify` detects edit/reorder/truncation | `internal/audit/*`, `cmd/audit.go`, RBAC interceptor emission | `internal/audit/*_test.go`, `internal/grpc/interceptor_audit_test.go` | ✅ — Phase 3.1 (2026-06-04) |
| T2.6 | D | Attacker establishes many slow-handshake connections to exhaust file descriptors | M | TLS handshake deadline (10s) + global (`MaxConns`) and per-device (`PerDeviceMaxConns`) connection caps via `connLimitListener`. Breach contract: reject + routine `limit.exceeded` audit event + `sentinel_limit_exceeded_total` metric. | `pkg/transport/connlimit.go`, `pkg/transport/mtls.go` | `pkg/transport/connlimit_test.go` | ✅ — mitigated Phase 3.2 (2026-06-04) |

### TB3 — MCP stdio

| ID | STRIDE | Threat | Sev | Mitigation | Code | Test | Status |
|----|--------|--------|-----|------------|------|------|--------|
| T3.1 | E | LLM-generated tool call invokes `exec` with a payload that breaks out of sandbox | C | All exec goes through binary allowlist + sandbox path validation; `rm -rf /` etc. blocked at parse | `internal/exec/`, `internal/sandbox/` | `internal/sandbox/sandbox_test.go` | ✅ |
| T3.2 | T | Malformed JSON-RPC over stdio crashes MCP server | M | JSON-RPC parser is the MCP go-sdk's; we add input validators per tool + native fuzz tests | `internal/mcp/server.go` | MCP fuzz tests (Phase 2b) | ❌ → Phase 2b |
| T3.3 | I | MCP tool output exfiltrates secrets the LLM tricks the daemon into reading | H | FS read allowlist; redaction layer for known-secret patterns in audit logs | `internal/fs/`, audit logger (Phase 3.1) | TBD | 🟡 — read allowlist exists; redaction is new |
| T3.4 | E | LLM calls many tools at once to amplify attack | M | Per-session rate limits on tool calls (already exists for some endpoints; extend to MCP) | rate limiter | TBD | 🟡 → Phase 3.2 |

### TB4 — Supervisor IPC

| ID | STRIDE | Threat | Sev | Mitigation | Code | Test | Status |
|----|--------|--------|-----|------------|------|------|--------|
| T4.1 | E | Compromised worker process sends crafted IPC to monitor to gain monitor privilege | H | IPC is one-way (worker → monitor) for status only; monitor never executes worker-supplied code | `internal/supervisor/` | `internal/supervisor/*_test.go` | ✅ |
| T4.2 | T | Worker crash leaves stale lockfiles / PID files that mislead future starts | L | Atomic write + stale-PID detection on startup | `internal/serverinfo/` | TBD | 🟡 |
| T4.3 | E | Worker spawned with elevated privilege (e.g., started as root) keeps them after socket bind | H | Privilege drop after socket bind on Unix | supervisor (Phase 3.3) | TBD | ❌ → Phase 3.3 |

### TB5 — Exec engine

| ID | STRIDE | Threat | Sev | Mitigation | Code | Test | Status |
|----|--------|--------|-----|------------|------|------|--------|
| T5.1 | E | Allowlisted binary is itself a code-execution vector (e.g., `python -c`) | C | OS confinement on Windows (Job Object + restricted token) via `internal/confine`; fail-closed on Windows, no-op+warn on Linux/macOS pending v2 (Landlock/seccomp). Layered on top of the binary allowlist (T3.1) — allowlist is necessary but not sufficient. | `internal/confine/` | `internal/confine/confine_windows_test.go` | 🟡 — Windows confinement shipped 2026-06-03 (Phase 3.6 v1); Linux/macOS native sandbox → v2 |
| T5.2 | E | Argument injection turns `git clone $URL` into something dangerous | H | Use `exec.Command` with explicit argv (never shell); validate URL/path arguments | `internal/exec/` | exec_test.go | ✅ |
| T5.3 | D | Spawned process runs forever / consumes all RAM | M | Fully mitigated cross-platform — Windows Job Object (existing) + Linux/macOS `RLIMIT_AS`/`RLIMIT_NOFILE`/`RLIMIT_CPU` via the re-exec trampoline (`internal/confine/confine_unix.go`, `cmd/confined_exec_unix.go`). Breach contract: reject + routine `limit.exceeded` audit event + `sentinel_limit_exceeded_total` metric. | `internal/confine/confine_unix.go`, `cmd/confined_exec_unix.go`, `internal/confine/` | `internal/confine/confine_unix_test.go`, `cmd/confined_exec_test.go` | ✅ — fully mitigated cross-platform Phase 3.2 (2026-06-04) |
| T5.4 | I | Spawned process inherits daemon's env (including secrets) | H | Whitelist-only env propagation to children | `internal/exec/` | exec_test.go | 🟡 — verify in audit |

### TB6 — FS sandbox

| ID | STRIDE | Threat | Sev | Mitigation | Code | Test | Status |
|----|--------|--------|-----|------------|------|------|--------|
| T6.1 | E | Path traversal via `../` escapes sandbox | C | All paths resolved to absolute via `filepath.Abs` + prefix check on cleaned path | `internal/sandbox/` | sandbox_test.go | ✅ |
| T6.2 | E | Symlink in sandbox points outside sandbox; write follows symlink | C | `O_NOFOLLOW` on writes; stat dest before open and reject non-regular files | `internal/fs/` | fs_test.go | 🟡 — audit coverage in Phase 1 |
| T6.3 | T | Race between path-check and open (TOCTOU) lets attacker swap target | H | Open by FD then `fstat`; never re-open by path | `internal/fs/` | fs_test.go | 🟡 — audit coverage in Phase 1 |
| T6.4 | I | Read allowlist lets attacker enumerate sensitive paths | M | Allowlist denies by default; entries are explicit prefixes | `internal/sandbox/` | sandbox_test.go | ✅ |

### TB7 — SQLite and on-disk state

| ID | STRIDE | Threat | Sev | Mitigation | Code | Test | Status |
|----|--------|--------|-----|------------|------|------|--------|
| T7.1 | I | Another user on the host reads sessions DB containing command history | H | Datadir is `0700`, files `0600`; documented; verify on startup | `internal/datadir/` | startup test | 🟡 — verify in audit |
| T7.2 | T | Attacker modifies sessions DB to plant fake checkpoints | M | Integrity HMAC on session checkpoints (out of scope v1, tracked) | — | — | ❌ → Backlog |
| T7.3 | R | No record of who started/stopped which session | M | Tamper-evident, actor-attributed, hash-chained security audit log; critical events fail-closed; `sentinel audit verify` detects edit/reorder/truncation | `internal/audit/*`, `cmd/audit.go`, RBAC interceptor emission | `internal/audit/*_test.go`, `internal/grpc/interceptor_audit_test.go` | ✅ — Phase 3.1 (2026-06-04) |

### TB8 — CA key store

| ID | STRIDE | Threat | Sev | Mitigation | Code | Test | Status |
|----|--------|--------|-----|------------|------|------|--------|
| T8.1 | I | Local attacker reads CA private key from disk | C | Encrypt CA key at rest using OS keystore (DPAPI / Keychain / libsecret) | `internal/security/crypto/` (Phase 3.4) | TBD | ❌ → Phase 3.4 |
| T8.2 | T | Attacker swaps CA key with their own | C | File mode `0600`; integrity HMAC checked at load; future: HSM (Backlog) | `internal/ca/` | ca_test.go | 🟡 → Phase 3.4 |
| T8.3 | R | CA signs a cert but no record of who/when | H | Tamper-evident, actor-attributed, hash-chained security audit log; critical events fail-closed; `sentinel audit verify` detects edit/reorder/truncation | `internal/audit/*`, `cmd/audit.go`, RBAC interceptor emission | `internal/audit/*_test.go`, `internal/grpc/interceptor_audit_test.go` | ✅ — Phase 3.1 (2026-06-04) |
| T8.4 | E | Old long-lived cert remains valid even after device is revoked | C | CRL file served on bootstrap port; mTLS handshake consults CRL | `pkg/transport/crl.go` (Phase 3.4) | TBD | ❌ → Phase 3.4 |

### TB9 — Auto-update channel

| ID | STRIDE | Threat | Sev | Mitigation | Code | Test | Status |
|----|--------|--------|-----|------------|------|------|--------|
| T9.1 | T | Attacker replaces the release artifact on the update channel | C | Cosign keyless signature verified before binary swap | self-update + cosign (Phase 3.3) | TBD | ❌ → Phase 3.3 |
| T9.2 | T | Attacker MITMs the update download | H | HTTPS + signature verification; pin transparency log entry | self-update (Phase 3.3) | TBD | ❌ → Phase 3.3 |
| T9.3 | E | Update downgrades to a known-vulnerable version | H | Reject artifacts with version lower than current | self-update (Phase 3.3) | TBD | ❌ → Phase 3.3 |

---

## Cross-Cutting Mitigations

These touch many boundaries and are tracked here rather than per-row:

| ID | Description | Implementing workstream |
|----|-------------|------------------------|
| X1 | Structured, hash-chained audit log for every privileged action | Phase 3.1 |
| X2 | Security metrics: auth failures, RBAC denials, sandbox violations, cert expiry | Phase 3.5 |
| X3 | Failed-login lockout (N failures in M minutes → device quarantine) | Phase 3.5 |
| X4 | SBOM + SLSA L3 provenance on every release | Phase 3.7 |

---

## Phase 3 Priorities Derived From This Model

Ranked by aggregated severity of unresolved threats they close:

1. **Phase 3.6 — OS sandbox** (T5.1: critical, only mitigation today is allowlist)
2. **Phase 3.4 — Crypto hardening** (T8.1, T8.2, T8.4, T2.3: 4 critical/high CA & cert threats)
3. **Phase 3.3 — Supervisor hardening + signed updates** (T9.1, T9.2, T9.3, T4.3)
4. **Phase 3.1 — Audit logging** (T2.5, T7.3, T8.3 plus regulatory hygiene)
5. **Phase 3.2 — Resource limits & DoS** (T1.3, T2.4, T2.6, T5.3)
6. **Phase 3.5 — Observability for security** (X2, X3, T3.4)
7. **Phase 3.7 — Supply chain** (X4 — pairs with 3.3)

The spec's original ordering is reaffirmed; sandbox + crypto hardening lead because they close the only remaining critical-severity threats.

---

## Out of Scope (Backlog)

- T7.2 — Session DB integrity HMAC
- HSM-backed CA key (replaces or augments T8.1 OS-keystore mitigation)
- Multi-CA federation (today: single per-operator CA)
- Network-layer DoS (mitigated by deployment topology, not the daemon)

---

## Maintenance

- Re-review this document whenever a new gRPC service, MCP tool, or trust boundary is added.
- Every Phase 3 PR must update the `Status` column for threats it closes (✅) and link the new test in the `Test` column.
- Whenever an entry moves to ✅, that change is part of the PR diff — not a separate doc bump.
