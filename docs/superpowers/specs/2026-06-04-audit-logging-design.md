# Phase 3.1 — Security Audit Log (Design)

**Date:** 2026-06-04
**Status:** Approved (owner sign-off 2026-06-04) — ready for implementation plan
**Spec lineage:** elaborates `docs/superpowers/specs/2026-05-22-hardening-design.md` §Phase 3 workstream 3.1
**Threats closed:** T2.5 / T7.3 (repudiation), T8.3 (audit-trail integrity) — see `docs/security/THREAT-MODEL.md`

---

## 1. Goal & Non-Goals

### Goal

A dedicated, tamper-evident, actor-attributed record of security-relevant events,
separate from operational logs and from functional session events. It must let an
operator answer, after the fact and with cryptographic confidence that the record
was not edited: **who** did **what**, **when**, against **which** resource, and
**whether it was allowed**.

### Non-Goals (v1 — deferred to backlog)

- Cryptographic **signing** of records (third-party non-repudiation). The hash chain
  gives tamper-*evidence*; signing gives tamper-*attribution to a key*. Layerable later
  on the same chain.
- gRPC `AuditService` (remote query/stream of the audit log).
- Remote / SIEM shipping (syslog, OTLP, S3) and fleet-wide audit aggregation.
- Real-time alerting on audit events (that is Phase 3.5 Observability).

These are explicitly out of scope so v1 stays a single, self-contained, local subsystem.

---

## 2. Architecture

### 2.1 Package & interface

New package `internal/audit`. Core surface:

```go
// Logger records security-relevant events to a tamper-evident store.
type Logger interface {
    // Record appends one event. It returns an error if the event could not be
    // durably written. Callers decide what to do with that error based on the
    // event's Criticality (see §5).
    Record(ctx context.Context, ev Event) error
    Close() error
}

type Criticality int

const (
    Routine  Criticality = iota // log-and-continue on write failure
    Critical                    // abort the triggering operation on write failure
)

type Outcome string

const (
    OutcomeAllow Outcome = "allow"
    OutcomeDeny  Outcome = "deny"
    OutcomeError Outcome = "error"
)

type Event struct {
    Type        string         // e.g. "pairing.accept", "rbac.deny", "cert.sign"
    Criticality Criticality
    Outcome     Outcome
    Target      string         // resource/subject acted on (device id, path, cert subject)
    Detail      map[string]any // structured, JSON-serializable context (no secrets)
}
```

Actor identity (`actor_device_id`, `actor_role`) is **not** a caller-supplied field —
it is extracted from the request context / peer certificate inside the logger so a
caller cannot forge the actor. A helper `audit.WithActor(ctx, deviceID, role)` seeds
the context at the RBAC interceptor / transport boundary; `Record` reads it back.

### 2.2 Emission pattern (injected, like the confiner)

The logger is injected into subsystems the same way `confine.Confiner` is, via
constructor wiring in `cmd/serve.go`:

- `internal/grpc` services (exec, fleet, session, payload, capture, worker) — via the
  RBAC interceptor and per-service structs.
- `pkg/transport` bootstrap (pairing accept/reject, cert sign).
- `internal/ca` (cert sign/renew, CA-pin operations) — through the caller, not the CA
  primitive itself, to keep `ca` dependency-free.
- `internal/sandbox` (path-validation denials, exec allowlist denials).
- `internal/exec` and `internal/worker` (command execution records, confinement refusals).
- `internal/fleet` (membership add/remove, CA-pin drift detected by `doctor`).

A **no-op logger** (`audit.NopLogger`) is the zero value used by existing callers and
tests, so wiring is purely additive and changes no existing behavior until the daemon
injects the real logger.

### 2.3 Why an explicit logger and not an slog Handler

A passive `slog.Handler` that siphons `audit=true` records out of the operational log
stream was considered and **rejected**: the tiered fail-closed posture (§5) requires the
*caller* to receive a write error and abort. An slog handler runs after the log call
returns and cannot signal the caller. An explicit `Record(...) error` is therefore
required, not a stylistic choice. The operational slog stream still receives a parallel
non-authoritative line for routine observability.

---

## 3. Storage & Record Schema

### 3.1 Store

A dedicated SQLite database, default `~/.sentinel/audit.db`, opened with WAL mode and
created with `0600` file permissions (stricter than the operational session/fleet DBs).
It is **never** shared with the session or fleet stores, so audit integrity is not
coupled to operational churn.

### 3.2 Table

```sql
CREATE TABLE IF NOT EXISTS audit_log (
    seq              INTEGER PRIMARY KEY AUTOINCREMENT, -- monotonic, gap = tamper signal
    ts               TEXT    NOT NULL,                  -- RFC3339Nano UTC
    actor_device_id  TEXT    NOT NULL,                  -- "" for system/self events
    actor_role       TEXT    NOT NULL,                  -- admin|operator|reader|system
    event_type       TEXT    NOT NULL,
    criticality      INTEGER NOT NULL,                  -- 0 routine, 1 critical
    outcome          TEXT    NOT NULL,                  -- allow|deny|error
    target           TEXT    NOT NULL,
    detail           TEXT    NOT NULL,                  -- canonical JSON, "{}" if empty
    segment          INTEGER NOT NULL,                  -- sealed-segment id (see §6)
    prev_hash        TEXT    NOT NULL,                  -- hash of seq-1 ("" only for genesis)
    hash             TEXT    NOT NULL                   -- this record's chain hash
);
CREATE INDEX IF NOT EXISTS idx_audit_ts      ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_type    ON audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_actor   ON audit_log(actor_device_id);
CREATE INDEX IF NOT EXISTS idx_audit_segment ON audit_log(segment);
```

A single-row `audit_meta` table holds `genesis_hash`, `last_seq`, `last_hash`, and the
current `segment` id for O(1) append without scanning.

---

## 4. Hash Chain & Verification

### 4.1 Construction

For each record, in canonical field order:

```
payload  = seq || ts || actor_device_id || actor_role || event_type ||
           criticality || outcome || target || detail || prev_hash
hash     = "sha256:" + hex(SHA-256(payload))
```

Canonicalization is explicit (fixed field order, NUL-separated, `detail` is canonical
JSON with sorted keys) so verification is deterministic across platforms. The **genesis**
record (first append to a fresh db) uses `prev_hash = ""` and is recorded in
`audit_meta.genesis_hash`. Each subsequent record's `prev_hash` = the prior record's
`hash`. Append is single-writer-serialized (a process-level mutex around the insert +
`audit_meta` update in one transaction).

### 4.2 Verification

`sentinel audit verify` walks the chain from genesis (or from the oldest retained
segment's anchor, §6) and reports the **first** broken link, classified as:

- **edit** — recomputed hash ≠ stored hash at `seq`.
- **reorder/forgery** — `prev_hash` at `seq` ≠ `hash` at `seq-1`.
- **truncation** — `last_seq` in meta > max(seq) present, or a sealed segment's anchor
  hash does not match its last retained record.

Exit non-zero on any break; print the offending `seq`, expected vs actual.

---

## 5. Failure Posture (Tiered)

`Record` returns an error on write failure. The **caller** acts on it by event tier:

| Tier | Events | On `Record` error |
|---|---|---|
| **Critical** | pairing accept/reject, RBAC grant/deny on admin ops, cert sign/renew, CA-pin change, sandbox-escape attempt, confinement refusal, daemon-trust changes | **Abort** the triggering operation; return an error to the client. Nothing security-relevant happens un-audited. |
| **Routine** | reads, ordinary exec, list/status RPCs, heartbeat, health | **Log-and-continue**: emit a loud `slog.Warn` once-per-window + increment `audit_write_failures_total`. The operation proceeds. |

This bounds the self-DoS surface (a full disk cannot wedge routine traffic) while
guaranteeing the high-value events are never silently lost. The criticality is a property
of the **event type** (a static catalog, §6.1), not a per-call decision, so it cannot be
downgraded by a caller.

---

## 6. Event Taxonomy & Retention

### 6.1 Initial catalog

Each event type has a fixed criticality. Initial set (extensible):

| event_type | tier | emitted from |
|---|---|---|
| `pairing.accept` / `pairing.reject` | critical | transport bootstrap |
| `pairing.conflict` (known peer, CA changed) | critical | `connect` / bootstrap guard |
| `rbac.deny` (any denied request) | critical | grpc RBAC interceptor |
| `rbac.allow.privileged` (admin/operator mutating op) | critical | grpc RBAC interceptor |
| `rbac.allow.read` (reader/list/status op) | routine | grpc RBAC interceptor |
| `cert.sign` / `cert.renew` | critical | CA caller / `renew` |
| `capin.change` | critical | fleet registry `SetCAPin` |
| `sandbox.deny` (path/allowlist) | critical | `internal/sandbox` |
| `confine.refuse` (unconfined abort) | critical | `internal/exec`, `internal/worker` |
| `exec.run` (command + binary + cwd) | routine | `internal/exec` |
| `fleet.add` / `fleet.remove` | critical | fleet registry |
| `daemon.start` / `daemon.stop` / `daemon.renew` | critical | `cmd/serve`, `cmd/renew` |
| `fs.read` (allowlist read) | routine | filesystem service |

`Detail` carries event-specific context (command argv, peer device id, cert subject,
denied path, role) — **never** secrets (keys, cert private material, env values flagged
sensitive). A small redaction allowlist governs which `Detail` keys may be recorded.

### 6.2 Retention via sealed segments

Rotation is by **sealed segment**, never partial edit:

1. The live segment accumulates records. When it reaches `segment_max` records (or a
   time bound), it is **sealed**: its terminal `hash` is written to an
   `audit_segments(segment_id, first_seq, last_seq, anchor_hash, sealed_at)` row.
2. A new segment begins; its first record's `prev_hash` is still the sealed segment's
   terminal hash, so the chain is unbroken across the seam.
3. Pruning (`retention_days`) drops **whole sealed segments** older than the window. The
   oldest *retained* segment's `anchor_hash` becomes the verification start point;
   `audit verify` validates from there forward. Pruning a sealed segment is itself a
   `routine` audit event (`audit.prune`).

This keeps the retained chain fully verifiable while bounding disk growth, and makes
"someone deleted records" detectable (a gap that is not a sealed-segment boundary).

---

## 7. CLI Surface

```
sentinel audit tail   [--follow] [--type T] [--actor ID] [--n 50]
sentinel audit query  --since <ts> --until <ts> [--type T] [--outcome deny] [--json]
sentinel audit verify [--from-segment N]        # exit non-zero on first break
sentinel audit export --format json|csv [--since ...] > file
```

`tail`/`query` are read-only over `audit.db`. `verify` is the integrity command an
operator (or CI) runs. `export` produces an offline artifact for external review.

---

## 8. Config

Additive `audit` block in `internal/settings`, migrated `CurrentConfigVersion` 2 → 3
(same additive pattern as the `confine` block):

```go
type AuditConfig struct {
    Enabled       bool   // default true
    DBPath        string // default ~/.sentinel/audit.db
    RetentionDays int    // default 90; 0 = keep forever
    SegmentMax    int    // records per segment before seal; default 10000
}
```

`Validate` rejects `RetentionDays < 0` and `SegmentMax < 1`. `Migrate` adds defaults for
configs written at version 2.

---

## 9. Testing Strategy (TDD)

Table-driven, red-green-refactor, per `internal/audit` and each integration point:

1. **Chain integrity** — append N records, `verify` passes; then mutate a `detail`,
   reorder a `prev_hash`, and delete a middle row → `verify` reports edit / reorder /
   truncation respectively at the right `seq`.
2. **Fail-closed critical** — inject a failing store; a `critical` event's caller path
   aborts and returns an error; the operation's side effect did **not** occur.
3. **Fail-open routine** — same failing store; a `routine` event proceeds, warns once,
   increments the metric.
4. **Actor attribution** — actor is read from context/peer cert, not caller args; a caller
   that tries to set a different actor cannot.
5. **Redaction** — a `Detail` carrying a sensitive key is dropped/redacted, not stored.
6. **Retention sealing** — fill past `SegmentMax`, confirm seal + anchor; prune an old
   segment, confirm the retained chain still `verify`s from the new anchor.
7. **Migration** — a v2 config loads, migrates to v3 with audit defaults; an existing
   `audit.db`-less daemon creates the db with `0600`.
8. **No-op default** — existing callers with `NopLogger` are unchanged (regression guard).

Cross-platform: file-permission assertion is Windows-aware (ACL check) vs Unix (mode bits).

---

## 10. Architecture Impact & Risk

- **New dependency direction:** subsystems depend on the `audit.Logger` *interface* only;
  the SQLite implementation lives in `internal/audit` and is wired once in `cmd/serve.go`.
  `internal/ca` stays audit-free (records emitted by its callers).
- **Write amplification:** one extra serialized SQLite insert per audited event. Bounded
  by WAL + single-writer mutex; routine events dominate and are fail-open, so latency
  cannot stall the hot path.
- **Clock dependence:** `ts` is wall-clock; the chain integrity does **not** depend on
  time monotonicity (it depends on `seq` + hashes), so clock skew cannot break `verify`.
- **Biggest risk:** an event added to the codebase but not to the §6.1 catalog is
  un-audited. Mitigation: a registry test enumerating `event_type` constants and asserting
  every one has a declared criticality, so adding an event without classifying it fails CI.

---

## 11. Deliverables Checklist

- [ ] `internal/audit`: `Logger`, `Event`, `NopLogger`, SQLite store, hash chain, verify.
- [ ] `audit.WithActor` context helper + extraction at RBAC/transport boundary.
- [ ] Event catalog with static criticality + registry-completeness test.
- [ ] Tiered fail-closed/-open wiring at each emission point.
- [ ] Sealed-segment retention + prune.
- [ ] `sentinel audit tail|query|verify|export` CLI.
- [ ] `AuditConfig` settings block + v2→v3 migration.
- [ ] `cmd/serve.go` wiring + `Close()` on shutdown (via `addCleanup`).
- [ ] Threat model update: T2.5/T7.3/T8.3 → mitigated; HARDENING-STATUS campaign entry.
- [ ] Full TDD suite (§9), `go build`/`vet`/`test`/`golangci-lint` green, linux cross-build.
