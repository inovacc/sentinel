# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Release artifacts (binaries + checksums) for tagged versions are published on the
[GitHub Releases](https://github.com/inovacc/sentinel/releases) page. Versions prior to
this changelog (≤ `v1.1.0`) are documented there via auto-generated release notes.

## [Unreleased]

A security-hardening campaign closing field-driven and threat-model gaps. See
`docs/security/THREAT-MODEL.md` and `docs/superpowers/HARDENING-STATUS.md` for the
full traceability.

### Added

- **Security audit log** (`internal/audit`) — a dedicated, hash-chained, tamper-evident
  record of security-relevant events (pairing, RBAC decisions, cert lifecycle, sandbox/
  confinement denials, fleet changes). Tiered fail-closed posture, actor identity bound to
  the verified peer certificate, sealed-segment retention, and a `sentinel audit
  tail|query|verify|export` CLI. Closes T2.5 / T7.3 (repudiation) and T8.3 (audit integrity).
- **Resource limits & DoS protection** (`internal/limits`) — secure-by-default, tunable
  `limits` config: per-IP bootstrap throttle (T1.3), TLS handshake timeout + global/
  per-device connection caps (T2.6), gRPC message-size / concurrent-stream caps and a
  configurable RPC rate limiter (T2.4), and cross-platform process rlimits via a re-exec
  trampoline (T5.3). Breaches are rejected, audited (`limit.exceeded`), and metered.
- **OS process confinement v1** (`internal/confine`) — Windows Job Object + restricted
  token, and Linux/macOS `setrlimit` enforcement, applied fail-closed to spawned processes
  (T5.1).
- **CA-trust hardening** — per-peer CA fingerprint pinning at pairing, rotation/MITM
  detection (`connect` refuses silent re-pair of a changed peer; `--force` to override),
  `doctor` fleet-trust probe, actionable mTLS error classification (`internal/clierr`), and
  bootstrap-closed-after-transition with a time-boxed `sentinel renew` recovery window.

### Changed

- gRPC `MaxRecvMsgSize` tightened from the 4 MB default to a configurable cap; the RPC rate
  limiter is no longer hardcoded.
- Config schema migrated to version 4 (additive `audit` and `limits` blocks).

### Security

- Bumped the Go toolchain to `1.26.4`, resolving reachable advisories (GO-2026-5039
  net/textproto, GO-2026-5037 crypto/x509); `govulncheck` clean.
- Added `Dockerfile` (distroless, non-root, static), `.dockerignore`, `CONTRIBUTING.md`,
  and `SECURITY.md`.
