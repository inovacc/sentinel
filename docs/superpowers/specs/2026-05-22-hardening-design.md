# Sentinel Hardening — Design

**Date:** 2026-05-22
**Owner:** Dyam Marcano
**Status:** Draft (awaiting user review)

---

## 1. Goal & Non-Goals

**Goal.** Bring Sentinel from "functional security-critical daemon" to "auditable, defense-in-depth hardened." Concretely: zero open auditor findings, documented threat model with mitigations traced to code, and seven defense-in-depth workstreams complete with tests.

**Non-goals.**
- No new product features (no new MCP tools, no new gRPC services, no new commands).
- No protocol-breaking changes to bootstrap/mTLS wire format. Cert renewal and CRL fit within the existing two-phase lifecycle.
- No third-party security audit/pentest in scope — that is a follow-up after this hardening lands.
- No formal compliance certification (SOC2 / FedRAMP) — but we produce artifacts (audit log, SBOM, threat model) that would feed one.

**Success criteria.**
1. `docs/quality/summary.json` shows `total: 0` after re-running the internal auditor.
2. `govulncheck`, `gosec`, `gitleaks`, `osv-scanner` all green in CI.
3. Threat model doc at `docs/security/THREAT-MODEL.md` with every threat → mitigation → code reference → test.
4. Fuzz tests run in CI nightly for protocol parsers; corpus committed.
5. All 7 defense-in-depth workstreams have: code + tests + ARCHITECTURE.md update + threat model entry.

---

## 2. Phasing — Approach B (vulns-first, then parallel tracks)

### Sprint 0 — Emergency vulns (1–2 days, blocks everything else)

- Bump Go toolchain to latest patch (resolves the 5 critical stdlib CVEs).
- `go get -u golang.org/x/net@latest` + `go mod tidy` (resolves remaining x/net CVEs).
- Re-run auditor; confirm `vuln` count drops to 0.
- Address the 6 `critical` auditor findings regardless of category (likely 1 critical bad-practice + 5 vuln items).
- Single commit, single PR, expedited review.

### Phase 1 — Auditor cleanup (parallel with Phase 2 & 3a)

Goal: drive `docs/quality/summary.json` total to 0.

- **1a.** Major bad-practices (159 items): batch by file/package; one PR per package or per rule family.
- **1b.** Cognitive complexity (12 hotspots, max 62): refactor functions over the auditor threshold. Extract helpers, table-drive switch statements, replace nested error returns with early returns. **Behavior preserved** — covered by existing tests + new tests where coverage is thin.
- **1c.** Modernize (1 finding): single commit.
- **1d.** Minor bad-practices (121 items): grouped commits, lowest priority.

Each commit must keep `go test ./...` and `golangci-lint run ./...` green.

### Phase 2 — Fresh audit (parallel with Phase 1 & 3a)

- **2a.** Add to CI: `gosec`, `govulncheck`, `gitleaks`, `osv-scanner`, `staticcheck` (verify it's in golangci-lint config; if not, add). Each tool fails the build on findings unless explicitly allowlisted with reason.
- **2b.** Protocol fuzz tests:
  - `pkg/transport/protocol.go` — length-prefixed JSON message parser.
  - `internal/mcp` — MCP JSON-RPC input validators.
  - `internal/grpc` — protobuf message validators (where custom validation exists).
  - Native Go fuzzing (`testing.F`). Corpus seeded from existing tests and committed under `testdata/fuzz/`.
  - CI runs each fuzz target for 60 seconds on PRs, 30 minutes nightly.
- **2c.** Threat model: produce `docs/security/THREAT-MODEL.md`. Format: STRIDE per trust boundary (bootstrap port, mTLS port, MCP stdio, supervisor IPC, exec engine, fs sandbox, fleet registry). Each threat row: `id | description | mitigation | code | test`. Drives Phase 3b ordering.

### Phase 3 — Defense-in-depth (7 workstreams)

Each workstream is independently mergeable. **3a items** can run parallel to Phases 1–2; **3b items** wait for the threat model.

| # | Workstream | Dependency | Notes |
|---|---|---|---|
| 3.1 | Audit logging | 3a | Structured, hash-chained, rotation. Every privileged action. Append-only file + optional syslog sink. |
| 3.2 | Resource limits & DoS | 3a | Per-session CPU/mem/FD caps via `prlimit` (Linux) / Job Objects (Windows). gRPC max message size. Slow-client deadlines on bootstrap. Tighten existing rate limits. |
| 3.3 | Supervisor hardening | 3a | Privilege drop after socket bind (Unix). Self-update signature verification via `cosign` (already produces releases). Core dump suppression for secrets. |
| 3.4 | Crypto hardening | 3a | CA key encryption at rest (DPAPI / Keychain / libsecret). Short-lived certs (default 30d, renewal flow already exists). CRL file served on bootstrap port. `subtle.ConstantTimeCompare` audit. |
| 3.5 | Observability for security | 3a | Prometheus metrics: `sentinel_auth_failures_total`, `sentinel_rbac_denials_total`, `sentinel_sandbox_violations_total`, `sentinel_cert_expiry_seconds`. Failed-login lockout (N failures in M minutes → device quarantine). |
| 3.6 | OS sandbox | 3b | Wrap exec engine. Linux: seccomp-bpf via `libseccomp-golang` (deny-by-default syscall list). Windows: Job Object + low integrity. macOS: `sandbox-exec` profile. Layered on top of the existing binary allowlist — sandbox is the second wall. |
| 3.7 | Supply chain | 3b | SBOM via `syft` on every release. SLSA L3 provenance via GitHub OIDC. Release artifacts signed with cosign keyless. Reproducible build verification job in CI. |

---

## 3. Architecture Impact

No protocol changes. New code lands in:

- `internal/audit/` — audit logger (new package, used by exec, fs, ca, rbac, session).
- `internal/security/limits/` — resource limit helpers (platform-split).
- `internal/security/sandbox/` — OS sandbox primitives (platform-split; existing `internal/sandbox/` keeps path-validation logic).
- `internal/security/crypto/` — at-rest encryption helpers (platform keystore wrappers).
- `internal/observability/` — security metrics (if no existing metrics package; otherwise add to existing).
- `pkg/transport/crl.go` — CRL fetch and check during mTLS handshake.
- `docs/security/THREAT-MODEL.md`
- `docs/security/AUDIT-LOG-SCHEMA.md`
- `.github/workflows/security.yml` — new tool runs.
- `testdata/fuzz/` — fuzz corpora.

Existing packages get small wiring changes (call audit log on privileged actions, apply resource limits before exec, etc.) but no structural rewrites beyond what the cognitive-complexity fixes in Phase 1 already entail.

---

## 4. Testing Strategy

- **Unit tests:** every new package, 80%+ coverage, table-driven.
- **Integration tests:** end-to-end scenarios per workstream (e.g., "RBAC denial produces audit log entry with matching trace ID"; "exec exceeding CPU limit is killed and recorded").
- **Fuzz tests:** Phase 2b, CI-enforced.
- **Negative tests for sandbox:** the test suite for 3.6 must include a "this command would escape without the sandbox" case that's expected to be killed by the sandbox layer.
- **Regression suite:** `go test ./... -race` clean. `golangci-lint run` clean. All Phase 2a tools clean.

---

## 5. Sequencing & Risk

- **Sprint 0 ships day 1–2.** Reduces real risk immediately (5 critical CVEs reachable).
- **Phases 1, 2a, 2b, and all 3a items run in parallel.** Different packages, low merge-conflict risk.
- **Phase 2c (threat model) blocks 3.6 and 3.7.** Both are design-sensitive — sandbox policy and supply-chain attestation choices flow from the threat model.
- **High-risk items:** cognitive-complexity refactors (1b) and OS sandbox (3.6). Both get extra-thorough tests and dedicated PRs.
- **Rollback story:** every workstream is feature-flagged or independently revertable. No big-bang merges.

---

## 6. Deliverables Checklist

- [ ] Sprint 0 PR (vulns fixed, criticals fixed)
- [ ] Phase 1 PRs (auditor total = 0)
- [ ] CI security workflow with 5 tools (Phase 2a)
- [ ] Fuzz tests + nightly job (Phase 2b)
- [ ] `docs/security/THREAT-MODEL.md` (Phase 2c)
- [ ] 7 × Phase 3 workstreams, each: code + tests + docs + threat-model row
- [ ] `docs/ARCHITECTURE.md` updated
- [ ] `docs/security/AUDIT-LOG-SCHEMA.md`
- [ ] Re-run auditor: 0 findings
- [ ] Re-run all Phase 2a tools: 0 findings

---

## 7. Out of Scope (Backlog)

- Third-party pentest engagement
- Hardware security module (HSM) for CA key
- Multi-tenant isolation (today: single operator fleet)
- Formal verification of protocol state machine
- FIPS 140-3 cryptography mode

These go to `docs/BACKLOG.md` with `SECURITY-FUTURE` tags.
