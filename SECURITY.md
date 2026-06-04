# Security Policy

Sentinel is a security-sensitive component: it runs a daemon that executes commands on behalf
of remote, authenticated peers. We take vulnerabilities seriously and appreciate responsible
disclosure.

## Reporting a vulnerability

**Please do not report security issues through public GitHub issues, discussions, or pull
requests.**

Instead, use **[GitHub's private vulnerability reporting](https://github.com/inovacc/sentinel/security/advisories/new)**
("Report a vulnerability" under the repository's *Security* tab). This opens a private
advisory visible only to the maintainers.

Please include:

- A description of the issue and its impact.
- Steps to reproduce (a minimal proof-of-concept if possible).
- Affected version / commit and platform.

We aim to acknowledge a report within **3 business days** and to provide a remediation
timeline after triage. Please give us a reasonable window to release a fix before any public
disclosure.

## Supported versions

Security fixes are applied to the latest released minor version. Older versions may not
receive backports.

| Version | Supported |
| ------- | --------- |
| `1.1.x` | ✅        |
| `< 1.1` | ❌        |

## Security model

Sentinel is built defense-in-depth; the threat model and per-threat mitigations are tracked
in [`docs/security/THREAT-MODEL.md`](docs/security/THREAT-MODEL.md). In brief:

- **Transport** — two-phase lifecycle: Syncthing-style self-signed bootstrap (port 7399) for
  pairing, then CA-signed **mutual TLS** (port 7400) for the data plane. The bootstrap port is
  closed after the mTLS transition and only reopened for an explicit, time-boxed `sentinel
  renew` window.
- **Identity & trust** — certificate-based device IDs; per-peer CA fingerprint **pinning**
  with rotation/MITM detection on re-pair.
- **Authorization** — role-based access control (admin / operator / reader) carried in an
  X.509 extension and enforced by a gRPC interceptor.
- **Sandbox** — writes/deletes confined to `~/.sentinel/sandbox/`; reads via allowlist; path
  traversal blocked; only allowlisted binaries may execute; destructive commands always
  denied.
- **OS confinement** — spawned processes are confined fail-closed (Windows Job Object +
  restricted token; Linux/macOS `setrlimit`).
- **DoS protection** — per-IP bootstrap throttling, TLS handshake timeouts, connection caps,
  gRPC message-size/rate limits, and process resource limits.
- **Auditability** — a hash-chained, tamper-evident security audit log (`sentinel audit
  verify` detects edits, reordering, and truncation).

## Disclosure of dependency advisories

Every CI run executes `govulncheck`, `gosec`, `gitleaks`, and `osv-scanner`. Known dependency
advisories are remediated by toolchain/dependency bumps.
