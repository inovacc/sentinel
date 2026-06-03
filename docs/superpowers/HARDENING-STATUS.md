# Hardening Status

**Branch:** `hardening/sprint0-vulns` (7 commits, ready for review/PR)
**Last updated:** 2026-05-30

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

1. **3.6 OS sandbox** — only mitigation for T5.1 (allowlisted-binary RCE) today is the binary allowlist.
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
