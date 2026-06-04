# Hardening Status

**Branch:** `hardening/sprint0-vulns` (7 commits, ready for review/PR)
**Last updated:** 2026-05-30

---

## Phase 3.1 — Security Audit Log (2026-06-04)

**Closes:** T2.5 / T7.3 (repudiation), T8.3 (audit-trail integrity).

**Delivered:**
- `internal/audit`: injected `Logger` (real `SQLiteLogger` + `NopLogger`), hash-chained tamper-evident store (`hash = "sha256:"+hex(SHA-256(canonical payload))`), `Verify` detecting edit/reorder/truncation, sealed-segment retention + prune, Detail redaction allowlist.
- Static event catalog with compile-checked criticality; tiered fail-closed posture (critical events abort the operation, routine events log-and-continue with a once-per-window warn + `audit_write_failures_total`).
- Emission wired into the RBAC interceptor (`rbac.allow.privileged`/`rbac.allow.read`/`rbac.deny`), exec/worker (`exec.run`, `confine.refuse`), fleet/pairing (`pairing.*`, `fleet.*`, `capin.change`, `cert.sign/renew`), sandbox (`sandbox.deny`), and daemon lifecycle (`daemon.start/stop/renew`).
- `sentinel audit tail|query|verify|export` CLI; `AuditConfig` settings block (config schema v2 → v3).
- Actor identity extracted from the verified peer certificate (anti-forgery), never from the request body.

**Deferred to backlog:** record signing (third-party non-repudiation), gRPC `AuditService`, SIEM/remote shipping, real-time alerting.

**Tests:** full TDD suite in `internal/audit/*_test.go`, `internal/grpc/interceptor_audit_test.go`, `internal/settings/settings_audit_test.go`, `cmd/audit_test.go`, `cmd/serve_audit_test.go`. `go build`/`vet`/`test` green; linux cross-build verified.

---

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

---

## 2026-06-03 — Phase 3.6 v1: OS process confinement (Windows)

**Branch:** `feature/os-sandbox`
**Spec:** `docs/superpowers/specs/2026-05-22-hardening-design.md` (Phase 3.6)
**Plan:** `docs/superpowers/plans/2026-06-03-os-sandbox.md`

Layers an OS sandbox on top of the binary allowlist so an allowlisted-but-dangerous
binary (e.g. `python -c`) can no longer use full host resources. New `internal/confine`
package exposes a `Confiner` (`Prepare`/`Confine`/`Supported`/`Close`); `confine.Decide`
picks a real confiner on Windows and a no-op everywhere else. A nil/no-op confiner stays
a pure no-op so existing behavior is unchanged.

| What | Detail | Closes |
|---|---|---|
| Confiner interface + no-op + fail-closed posture | `internal/confine/confine.go`, `confine_other.go` | T5.1 scaffolding |
| Windows Job Object | active-process / committed-memory / CPU-rate caps + kill-on-close | T5.1, T5.3 (process/memory/CPU caps on Windows) |
| Windows restricted token | drops admin SID + dangerous privileges on the spawned process | T5.1 (privilege reduction) |
| Config block + migration | `confine` settings (mode/limits) with additive migration | — |
| Exec + worker integration | `exec.Runner` and `worker.Pool` apply the confiner fail-closed on Windows | T5.1 |
| Daemon wiring | `cmd/serve.go` builds the confiner (real on Windows, no-op elsewhere) and closes it on shutdown | — |

**Posture:** fail-closed on Windows (a confinement error aborts the exec); no-op + one-time
warn on Linux/macOS. Confinement here is a **shared** Job Object with kill-on-daemon-exit —
the documented v1 limitation.

**Remaining:** v2 — Linux native sandbox (Landlock/seccomp) and macOS (`sandbox-exec`);
v3 — Windows AppContainer / container-per-exec isolation.

All changes TDD'd (table-driven); Windows-tagged files typecheck via
`GOOS=windows go build ./internal/confine/`. `go build`/`vet`/`test` green.

---

## 2026-06-03 — Evidence-driven CA-trust hardening

**Branch:** `hardening/evidence-ca-trust` (7 commits off `main`)
**Input:** field-failure bundle `F:\evicende_sentinel` — a peer rotated its CA; its
`:7400` daemon kept serving the stale server cert, so every paired client's data
plane broke with `x509: certificate signed by unknown authority`, while
`sentinel doctor` reported all-green throughout.
**Full findings:** `docs/security/EVIDENCE-HARDENING-FINDINGS.md` (27 confirmed,
0 refuted; 34-agent investigation + per-finding adversarial verification).

The failure exposed that Sentinel could neither **detect**, **diagnose**, nor
**recover** from a CA-trust mismatch. This campaign closes that chain:

| Commit | What | Closes |
|---|---|---|
| `ded49ed` | toolchain `1.26.3 → 1.26.4` | reachable CVEs GO-2026-5039 (net/textproto), GO-2026-5037 (crypto/x509); govulncheck clean |
| `e62a526` | pin per-peer CA fingerprint at pairing (`ca.Fingerprint`, registry `CAFingerprint`/`CACertPEM` + additive migration, `SetCAPin`) | makes rotation **detectable** (was: undetectable) |
| `8fff298` | `internal/clierr` classifies x509/handshake errors → actionable remediation; root `SilenceUsage`/`SilenceErrors` + `Execute` prints `clierr.Explain` | raw x509 + cobra-usage dump → **diagnosable** |
| `57f23a0` | `connect` refuses to silently re-pair a known peer whose CA changed (`pairingConflict`, check **before** `SaveMTLS`); `--force` to override | 2nd CRITICAL: connect-time rotation/MITM accepted silently |
| `b4a2371` | `doctor` `checkFleetTrust` probes each pinned peer's mTLS and verifies against the pinned CA | doctor blind-spot (all-green while data plane dead) |
| `b0f8d4a` | `serve` closes bootstrap after mTLS transition (`shouldOpenBootstrap`); `serve --renew-certs` + new `sentinel renew` (time-boxed window) | always-open bootstrap surface; **recovery** path |

Scope chosen by the owner: clusters A+B+C+D+E (detect → diagnose → recover),
secure-default bootstrap lifecycle. Deferred (owner's call): full CRL/OCSP
revocation, CA-rotation trust-overlap window, cryptographic device-ID binding,
broader RBAC/EKU scoping (clusters F/G in the findings doc).

All changes are TDD'd (table-driven), `go build`/`vet`/`test`/`govulncheck` green.

---

## Done

| Commit | Phase | Description |
|---|---|---|
| `86456dd` | Sprint 0 | Resolve 5 reachable CVEs via Go 1.26.3 toolchain + `x/net` v0.55.0. `govulncheck` clean. |
| `2344c2e` | Phase 2a | New `.github/workflows/security.yml`: govulncheck, gosec, gitleaks, osv-scanner. Bump CI/release to Go 1.26. |
| `cb97102` | Phase 2c | `docs/security/THREAT-MODEL.md` — STRIDE × 9 trust boundaries, mitigations traced to code/tests. |
| `192b757` | Phase 2b | `DecodeEnvelope` fuzz-testable entry point + `FuzzDecodeEnvelope` + 60s smoke + 30min nightly fuzz job. |
| `10bd93d` | Phase 2c | Mark T1.4 closed in threat model. |
| `52e2473` | Phase 1 | BP004 discarded-error fixes on trust/persistence paths (bootstrap MsgComplete, serve Serve(), logrotate rename/remove + first tests, worker persistence/decode). |
| `153a70d` | Phase 1 | Thread daemon logger into ExecService; dropped session audit events (checkpoint/error/command/stream) now logged — closes repudiation gap T2.5/T7.3. |
| `2f32aa2` | Phase 1 | (branch `hardening/serve-refactor`) Refactor `runDaemon` cognitive complexity 62 → 12 via build/serve split; closes the sole critical finding. First `cmd` boot smoke-tests. |

**Net result:**
- 0 known reachable CVEs (was 5 critical).
- New baseline security tooling running on every PR.
- Threat model is the single source of truth for what's protected vs. open.

## Open — sequenced by threat-model severity

Spec: `docs/superpowers/specs/2026-05-22-hardening-design.md`

### Phase 1 — Auditor cleanup

After Sprint 0, `docs/quality/` should be re-run; the 5 critical vulns drop off. The
`docs/quality/` artifacts on disk are **stale** (still list the 9 resolved CVEs) — re-run the
external auditor (`pkg/sonarlint` is not in this repo) before trusting its counts.

**BP004 (discarded errors) — triaged and partially fixed (commits `52e2473`, `153a70d`).**
The auditor flags *all* `_ = f()`, but the house style guide (CLAUDE.md) explicitly sanctions
muting deferred `Close()`/`Flush()` and `fmt.Fprint` to std streams. Triage of the 105 production
discards: **68 are sanctioned mutes — left as-is by design**; the meaningful ones (handshake
completion, bootstrap Serve, log-rotation, worker persistence, exec audit events) are fixed.
Remaining BP004 worth a follow-up (all low severity, no logger in scope):
- `internal/fleet/registry.go:224,238` and `internal/worker/pool.go:532,533` — `json.Unmarshal`
  in logger-less scan helpers. Thread a logger or make them `*Pool`/`*Registry` methods.
- Best-effort cleanup discards (`os.Remove` of temp screenshots, `Process.Kill/Release`,
  `RemovePID`, `metricsServer.Shutdown`, transport listener `Close`) — defensible as mutes;
  promote to Debug logs only if forensics needs them.
- 38 `_test.go` discards — review case-by-case (low value).

**Done (branch `hardening/serve-refactor`, commit `2f32aa2`):**
- ~~1 critical: `runDaemon` cognitive complexity 62~~ → **resolved**. Split into
  `runDaemonCtx` → `buildDaemon` (wiring) + `(*daemon).serve` (listen/block) with extracted
  helpers (`loadDeviceIdentity`, `openDataStores`, `buildTransport`, `setupLogging`,
  `warnCertExpiry`, `loadOrCreateBootstrapIdentity`, `buildOnPeerAccepted`,
  `startHeartbeatMonitor`, `startMetricsServer`, `registerServices`). Measured with `gocognit`:
  no function in `serve.go` exceeds 15 (buildDaemon = 12). Added the package's first tests
  (boot-and-shutdown smoke test on ephemeral ports). `settings.Listen.Bootstrap` added
  (port was hardcoded); `SENTINEL_SKIP_PUBLIC_IP` added to skip the startup-blocking outbound probe.

**Still open:**
- 11 other cognitive-complexity *majors* (bootstrap `handleConn`/`Connect`, fs `Grep`/`grepFile`/`ListDir`,
  session `selectSessions`, etc.) — refactor opportunistically.
- 11 BP002 (too many params), 109 BP006 (magic numbers), 2 BP001.
- 64 findings live in generated `internal/api/v1/*.pb.go` — exclude via auditor config; not our code.

### Phase 3 priority order (from threat model)

1. **3.6 OS sandbox** — v1 shipped on Windows (Job Object + restricted token, `internal/confine`); v2 (Linux/macOS native) still open. Was: only mitigation for T5.1 (allowlisted-binary RCE) was the binary allowlist.
2. **3.4 Crypto hardening** — closes T8.1/T8.2/T8.4/T2.3 (CA key at rest, cert revocation, short-lived certs).
3. **3.3 Supervisor hardening + signed updates** — closes T9.x (auto-update integrity) and T4.3 (privilege drop).
4. **3.1 Audit logging** — closes T2.5/T7.3/T8.3 (forensics/repudiation).
5. **3.2 Resource limits & DoS** — closes T1.3/T2.4/T2.6/T5.3.
6. **3.5 Observability for security** — closes X2/X3 plus T3.4.
7. **3.7 Supply chain (SBOM + SLSA)** — pairs with 3.3.

## How to continue

```bash
# Re-run baseline checks
govulncheck ./...
go test ./... -race
golangci-lint run ./...

# Verify security workflow still passes locally
go test ./pkg/transport/ -run='^$' -fuzz=FuzzDecodeEnvelope -fuzztime=60s
```

Each Phase 3 workstream should get its own plan in `docs/superpowers/plans/` and its own branch off `main` (after this branch lands).

## Notes for reviewers

- Branch is not pushed; push when you're ready to open a PR.
- The 5 commits are intentionally independent — they can be split into 5 PRs or merged as one stack.
- `docs/quality/` is gitignored / untracked because it's tool-generated. The hardening campaign treats those files as input artifacts, not source of truth.
- gosec / gitleaks / osv-scanner will fail their first CI run on findings not yet triaged. That's expected; first-run findings are the next backlog.
