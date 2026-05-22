# Sprint 0 — Emergency Vuln Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve all 9 `govulncheck` findings (5 critical, 4 major) and the 6 critical auditor findings in `docs/quality/`, restoring a clean vuln baseline before broader hardening begins.

**Architecture:** Dependency-only changes. Bump `golang.org/x/net` to latest, bump Go toolchain directive in `go.mod` to the latest patch covered by the 5 stdlib CVEs, then re-run the internal auditor and fix any remaining critical-severity items.

**Tech Stack:** Go 1.26+, `golang.org/x/vuln/cmd/govulncheck`, internal auditor at `pkg/sonarlint`.

**Spec:** `docs/superpowers/specs/2026-05-22-hardening-design.md`

---

### Task 1: Baseline — verify current vuln state

**Files:**
- Read only: `go.mod`, `docs/quality/summary.json`, `docs/quality/vulnerabilities.md`

- [ ] **Step 1: Record current state**

Run:
```bash
go version
grep -E "^(go |toolchain )" go.mod
grep "golang.org/x/net" go.mod
```

Expected (current known state): Go 1.26.2 runtime, `go 1.25.0` directive, `golang.org/x/net v0.50.0 // indirect`.

- [ ] **Step 2: Install and run govulncheck**

Run:
```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./... > /tmp/vuln-before.txt 2>&1; echo "exit=$?"
```

Expected: non-zero exit with findings matching the 9 IDs in `docs/quality/vulnerabilities.md` (GO-2026-4559, 4918, 4971, 4980, 4982, 4976, 4977, 4981, 4986).

---

### Task 2: Bump toolchain and dependencies

**Files:**
- Modify: `go.mod`
- Modify: `go.sum` (regenerated)

- [ ] **Step 1: Bump go directive and toolchain in go.mod**

Edit `go.mod`:
- Change `go 1.25.0` → `go 1.26.0`
- Add (or update) line `toolchain go1.26.2`

- [ ] **Step 2: Upgrade golang.org/x/net**

Run:
```bash
go get golang.org/x/net@latest
go mod tidy
```

- [ ] **Step 3: Verify build still works**

Run:
```bash
go build ./...
```

Expected: exit 0, no errors.

- [ ] **Step 4: Run tests**

Run:
```bash
go test ./... -race -count=1
```

Expected: all green. If a test breaks due to API drift in x/net, fix the call site (don't pin x/net back).

---

### Task 3: Re-run govulncheck — confirm 0 vulns

- [ ] **Step 1: Re-run vuln check**

Run:
```bash
govulncheck ./... > /tmp/vuln-after.txt 2>&1; echo "exit=$?"
```

Expected: exit 0, "No vulnerabilities found."

If any vuln remains:
- For a reachable stdlib vuln: bump `toolchain` directive in `go.mod` to the latest patch that includes the fix; retry from Task 2 Step 3.
- For a reachable third-party vuln: `go get <module>@latest` and retry.
- Do NOT add an exclusion; the goal is 0 findings.

---

### Task 4: Re-run internal auditor — fix remaining criticals

**Files:**
- Inspect: `docs/quality/summary.json`, `docs/quality/bad-practices.md`, `docs/quality/AI-FIX-INSTRUCTIONS.md`

- [ ] **Step 1: Re-run auditor**

Identify the auditor entry point. Check for one of:
```bash
task --list | grep -i audit
grep -rn "package sonarlint" pkg/sonarlint | head
ls cmd/ | grep -i audit
```

Run the auditor according to the discovered entry point (likely `go run ./cmd/<auditor>` or `task audit`).

- [ ] **Step 2: Read post-fix critical findings**

```bash
jq '.counts' docs/quality/summary.json
```

Expected after Tasks 2-3: `vuln: 0`. There may still be `critical: 1` (the non-vuln critical bad-practice) — read `docs/quality/bad-practices.md` and locate the entry with `severity: critical`.

- [ ] **Step 3: Fix any remaining critical bad-practices**

For each remaining critical-severity entry:
1. Read the file:line referenced.
2. Read the rule explanation in `docs/quality/AI-FIX-INSTRUCTIONS.md` (search for the rule ID).
3. Apply the documented fix.
4. Re-run `go test ./... -race -count=1` after each fix — must stay green.

- [ ] **Step 4: Final auditor re-run**

Re-run the auditor. Verify:
```bash
jq '.counts.critical, .counts.vuln' docs/quality/summary.json
```

Expected: `0` and `0`.

---

### Task 5: Commit Sprint 0

- [ ] **Step 1: Stage and commit**

```bash
git add go.mod go.sum docs/quality/
git add -A   # any source fixes from Task 4
git status
```

Verify only expected files staged. Then:

```bash
git commit -m "fix(security): sprint 0 - resolve 9 CVEs and critical auditor findings

- Bump go directive to 1.26.0 and toolchain to go1.26.2
- Upgrade golang.org/x/net to latest (resolves GO-2026-4559/4918/4976/4977/4981/4986)
- Stdlib CVEs resolved by toolchain bump (GO-2026-4971/4980/4982)
- Fix remaining critical-severity auditor findings

Spec: docs/superpowers/specs/2026-05-22-hardening-design.md
Refs: docs/quality/vulnerabilities.md"
```

- [ ] **Step 2: Verify clean tree**

```bash
git status
```

Expected: "working tree clean" (or only `docs/quality/` regeneration artifacts if the auditor re-ran).

---

## Done Criteria

- `govulncheck ./...` → exit 0, 0 findings
- `docs/quality/summary.json` → `vuln: 0`, `critical: 0`
- `go test ./... -race -count=1` → green
- `golangci-lint run ./... --timeout=5m` → green
- Single commit on `main` with the changes
