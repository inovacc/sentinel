# Hardening Status

**Branch:** `hardening/sprint0-vulns` (5 commits, ready for review/PR)
**Last updated:** 2026-05-22

## Done

| Commit | Phase | Description |
|---|---|---|
| `86456dd` | Sprint 0 | Resolve 5 reachable CVEs via Go 1.26.3 toolchain + `x/net` v0.55.0. `govulncheck` clean. |
| `2344c2e` | Phase 2a | New `.github/workflows/security.yml`: govulncheck, gosec, gitleaks, osv-scanner. Bump CI/release to Go 1.26. |
| `cb97102` | Phase 2c | `docs/security/THREAT-MODEL.md` — STRIDE × 9 trust boundaries, mitigations traced to code/tests. |
| `192b757` | Phase 2b | `DecodeEnvelope` fuzz-testable entry point + `FuzzDecodeEnvelope` + 60s smoke + 30min nightly fuzz job. |
| `10bd93d` | Phase 2c | Mark T1.4 closed in threat model. |

**Net result:**
- 0 known reachable CVEs (was 5 critical).
- New baseline security tooling running on every PR.
- Threat model is the single source of truth for what's protected vs. open.

## Open — sequenced by threat-model severity

Spec: `docs/superpowers/specs/2026-05-22-hardening-design.md`

### Phase 1 — Auditor cleanup (278 remaining findings)

After Sprint 0, `docs/quality/` should be re-run; the 5 critical vulns drop off. Remaining:
- 1 critical: `runDaemon` cognitive complexity 62 (cmd/serve.go) — refactor into helpers.
- 144 major bad-practices (BP004 = discarded errors). Most security-relevant; do these next.
- 11 BP002 (too many params), 109 BP006 (magic numbers), 1 BP001, 1 modernize.
- 64 findings live in generated `internal/api/v1/*.pb.go` — exclude via auditor config; not our code.
- 52 findings in `_test.go` files — review case-by-case.

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
