# Phase 3.1 — Security Audit Log Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a dedicated, tamper-evident, actor-attributed security audit log (`internal/audit`) with a SQLite hash-chained store, tiered fail-closed emission wired into every security-relevant code path, sealed-segment retention, a `sentinel audit` CLI, and threat-model closure for T2.5/T7.3/T8.3.

**Architecture:** A new `internal/audit` package exposes an injected `Logger` interface (mirroring `internal/confine.Confiner`: real impl wired in `cmd/serve.go`, `NopLogger` zero-value everywhere else). Events carry a static `Criticality` from a compile-checked catalog. The SQLite-backed `SQLiteLogger` appends records under a single-writer mutex, each chained by `hash = "sha256:"+hex(SHA-256(canonicalPayload))`. Callers act on `Record` errors by tier: critical events abort the triggering operation, routine events log-and-continue. Retention rotates whole sealed segments so the retained chain stays verifiable.

**Tech Stack:** Go 1.26, `modernc.org/sqlite` (pure-Go driver, already a dependency), `crypto/sha256`, `encoding/json` (canonical sorted-key detail), `log/slog`, Cobra CLI, table-driven tests with `t.TempDir()`.

---

## File Structure

| File | Responsibility |
|------|----------------|
| `internal/audit/audit.go` | `Logger`/`Outcome`/`Criticality`/`Event` types; `NopLogger`; `WithActor`/`actorFromContext` context helpers. The interface + zero-value, mirroring `confine.go`. |
| `internal/audit/catalog.go` | Event-type string constants + `CriticalityOf(eventType)` static catalog map + `Tier(eventType)` lookup; the single source of truth for which events are critical. |
| `internal/audit/redact.go` | `Detail` redaction allowlist: `redactDetail(map[string]any) map[string]any` drops keys not on the allowlist and replaces flagged-sensitive keys with `"[redacted]"`. |
| `internal/audit/hashchain.go` | `canonicalPayload(rec)` (fixed field order, NUL-separated, sorted-key JSON detail) + `computeHash(payload)` returning `"sha256:"+hex`. Pure functions, no DB. |
| `internal/audit/store.go` | `SQLiteLogger`: `Open`, schema creation, `0600` perms, `audit_meta` genesis, `Append` (insert + meta update in one txn under a mutex), `Record` (build event → actor → redact → tier → append → mirror slog → return tier-aware error), `Close`, write-failure metric + `warnOnce`. |
| `internal/audit/segment.go` | Sealed-segment logic: `maybeSeal` on `SegmentMax`, `audit_segments` row writes, `Prune(retentionDays)` dropping whole old segments, emitting `audit.prune`. |
| `internal/audit/verify.go` | `Verify(fromSegment int)`: walks chain from genesis or a segment anchor, returns first `*VerifyBreak{Seq, Kind, Expected, Actual}` (edit / reorder / truncation) or nil. |
| `internal/audit/query.go` | Read-only helpers: `Tail`, `Query` (time/type/outcome filters), `Export` (json/csv). Used only by the CLI. |
| `internal/settings/settings.go` | Add `AuditConfig` + `Audit` field + defaults + `Validate` rules; bump `CurrentConfigVersion` 2 → 3; `Migrate` step. |
| `cmd/audit.go` | `sentinel audit tail|query|verify|export` Cobra command group, matching `cmd/doctor.go` style. |
| `cmd/serve.go` | Build `audit.SQLiteLogger` from config, `addCleanup(Close)`, inject into interceptor / runner / pool / fleet / transport; emit `daemon.start`/`daemon.stop`. |
| `cmd/renew.go` | Emit `daemon.renew` + `cert.renew` around the renewal window. |
| `internal/grpc/interceptor.go` | Seed `WithActor` from the peer cert; emit `rbac.allow.privileged` / `rbac.allow.read` / `rbac.deny` with tiered fail-closed. |
| `internal/grpc/server.go` | Carry an `audit.Logger` into the interceptor constructors. |
| `internal/exec/exec.go` | Emit `exec.run` (routine) and `confine.refuse` (critical). |
| `internal/worker/pool.go` | Emit `confine.refuse` (critical) on unconfined-spawn abort. |
| `internal/sandbox/sandbox.go` | No code change; deny emission happens at the gRPC service boundary (see Task 9) to keep `sandbox` dependency-free. |
| `docs/security/THREAT-MODEL.md` | Flip T2.5/T7.3/T8.3 to mitigated, cite `internal/audit`. |
| `docs/superpowers/HARDENING-STATUS.md` | Add a Phase 3.1 campaign-status section. |

---

## Task 1: Event types, Logger interface, NopLogger, and the static catalog

**Files:**
- Create: `internal/audit/audit.go`
- Create: `internal/audit/catalog.go`
- Test: `internal/audit/catalog_test.go`

- [ ] **Step 1: Write the failing test (registry-completeness + tier split)**

Create `internal/audit/catalog_test.go`:

```go
package audit

import "testing"

func TestEveryCatalogEventHasCriticality(t *testing.T) {
	// allEventTypes is the exhaustive list of event-type constants. Every one
	// MUST be classified in the catalog, or adding an event without a tier
	// silently produces an un-audited (or mis-tiered) record.
	for _, et := range allEventTypes() {
		crit, ok := CriticalityOf(et)
		if !ok {
			t.Errorf("event type %q is not classified in the catalog", et)
			continue
		}
		if crit != Routine && crit != Critical {
			t.Errorf("event type %q has invalid criticality %d", et, crit)
		}
	}
}

func TestTierMatchesSpec(t *testing.T) {
	tests := []struct {
		eventType string
		want      Criticality
	}{
		{EventPairingAccept, Critical},
		{EventPairingReject, Critical},
		{EventPairingConflict, Critical},
		{EventRBACDeny, Critical},
		{EventRBACAllowPrivileged, Critical},
		{EventRBACAllowRead, Routine},
		{EventCertSign, Critical},
		{EventCertRenew, Critical},
		{EventCAPinChange, Critical},
		{EventSandboxDeny, Critical},
		{EventConfineRefuse, Critical},
		{EventExecRun, Routine},
		{EventFleetAdd, Critical},
		{EventFleetRemove, Critical},
		{EventDaemonStart, Critical},
		{EventDaemonStop, Critical},
		{EventDaemonRenew, Critical},
		{EventFSRead, Routine},
		{EventAuditPrune, Routine},
	}
	for _, tt := range tests {
		got, ok := CriticalityOf(tt.eventType)
		if !ok {
			t.Errorf("%s: not in catalog", tt.eventType)
			continue
		}
		if got != tt.want {
			t.Errorf("%s: tier = %d, want %d", tt.eventType, got, tt.want)
		}
	}
}

func TestUnknownEventTypeIsNotClassified(t *testing.T) {
	if _, ok := CriticalityOf("totally.unknown.event"); ok {
		t.Fatal("unknown event type unexpectedly classified")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/audit/ -run TestEveryCatalogEventHasCriticality -v`
Expected: FAIL — build error, `undefined: allEventTypes`, `undefined: CriticalityOf`, `undefined: EventPairingAccept`, `undefined: Routine`.

- [ ] **Step 3: Write the types (`audit.go`)**

Create `internal/audit/audit.go`:

```go
// Package audit records security-relevant events to a tamper-evident,
// actor-attributed store, separate from operational logs and session events.
//
// The Logger interface is injected the same way internal/confine.Confiner is:
// the real SQLite-backed implementation is wired once in cmd/serve.go, and a
// NopLogger zero value is used by every other caller and by tests, so wiring is
// purely additive and changes no existing behavior until the daemon injects the
// real logger.
package audit

import "context"

// Criticality is a static property of an event type (see catalog.go). It tells
// the caller what to do when Record fails: abort the operation (Critical) or
// log-and-continue (Routine).
type Criticality int

const (
	// Routine events log-and-continue on write failure.
	Routine Criticality = iota
	// Critical events abort the triggering operation on write failure.
	Critical
)

// Outcome is whether the audited action was allowed, denied, or errored.
type Outcome string

const (
	OutcomeAllow Outcome = "allow"
	OutcomeDeny  Outcome = "deny"
	OutcomeError Outcome = "error"
)

// Event is one security-relevant record. Actor identity is NOT a field here: it
// is extracted from the context inside Record (see WithActor) so a caller cannot
// forge the actor.
type Event struct {
	Type    string         // an Event* constant from catalog.go
	Outcome Outcome        // allow | deny | error
	Target  string         // resource/subject acted on (device id, path, cert subject)
	Detail  map[string]any // structured, JSON-serializable context; redacted before storage
}

// Logger records security-relevant events to a tamper-evident store.
type Logger interface {
	// Record appends one event. It returns an error if the event could not be
	// durably written. Callers decide what to do with that error based on the
	// event type's Criticality (see catalog.go and the tiered posture in §5 of
	// the design).
	Record(ctx context.Context, ev Event) error
	Close() error
}

// NopLogger is the zero-value Logger: it records nothing and never errors. It is
// the default for callers and tests so audit wiring is additive.
type NopLogger struct{}

func (NopLogger) Record(context.Context, Event) error { return nil }
func (NopLogger) Close() error                         { return nil }

// actor carries the authenticated identity of the request originator.
type actor struct {
	deviceID string
	role     string
}

type actorKey struct{}

// WithActor seeds the request context with the authenticated actor. It is called
// at the RBAC interceptor / transport boundary, where the peer certificate is
// available; Record reads it back so the actor cannot be supplied (and thus
// forged) by an ordinary caller.
func WithActor(ctx context.Context, deviceID, role string) context.Context {
	return context.WithValue(ctx, actorKey{}, actor{deviceID: deviceID, role: role})
}

// actorFromContext returns the seeded actor, or the system actor ("", "system")
// when none was set (self/daemon-originated events).
func actorFromContext(ctx context.Context) actor {
	if a, ok := ctx.Value(actorKey{}).(actor); ok {
		return a
	}
	return actor{deviceID: "", role: "system"}
}
```

- [ ] **Step 4: Write the catalog (`catalog.go`)**

Create `internal/audit/catalog.go`:

```go
package audit

// Event type constants. Every constant here MUST appear in the catalog map
// below with a declared criticality; the registry-completeness test enforces it.
const (
	EventPairingAccept       = "pairing.accept"
	EventPairingReject       = "pairing.reject"
	EventPairingConflict     = "pairing.conflict"
	EventRBACDeny            = "rbac.deny"
	EventRBACAllowPrivileged = "rbac.allow.privileged"
	EventRBACAllowRead       = "rbac.allow.read"
	EventCertSign            = "cert.sign"
	EventCertRenew           = "cert.renew"
	EventCAPinChange         = "capin.change"
	EventSandboxDeny         = "sandbox.deny"
	EventConfineRefuse       = "confine.refuse"
	EventExecRun             = "exec.run"
	EventFleetAdd            = "fleet.add"
	EventFleetRemove         = "fleet.remove"
	EventDaemonStart         = "daemon.start"
	EventDaemonStop          = "daemon.stop"
	EventDaemonRenew         = "daemon.renew"
	EventFSRead              = "fs.read"
	EventAuditPrune          = "audit.prune"
)

// catalog maps every known event type to its static criticality. This is the
// single source of truth for the tiered fail-closed posture: criticality is a
// property of the event type, not a per-call decision, so a caller cannot
// downgrade a critical event.
var catalog = map[string]Criticality{
	EventPairingAccept:       Critical,
	EventPairingReject:       Critical,
	EventPairingConflict:     Critical,
	EventRBACDeny:            Critical,
	EventRBACAllowPrivileged: Critical,
	EventRBACAllowRead:       Routine,
	EventCertSign:            Critical,
	EventCertRenew:           Critical,
	EventCAPinChange:         Critical,
	EventSandboxDeny:         Critical,
	EventConfineRefuse:       Critical,
	EventExecRun:             Routine,
	EventFleetAdd:            Critical,
	EventFleetRemove:         Critical,
	EventDaemonStart:         Critical,
	EventDaemonStop:          Critical,
	EventDaemonRenew:         Critical,
	EventFSRead:              Routine,
	EventAuditPrune:          Routine,
}

// CriticalityOf returns the static criticality for an event type. ok is false
// for an unknown (unclassified) event type.
func CriticalityOf(eventType string) (Criticality, bool) {
	c, ok := catalog[eventType]
	return c, ok
}

// allEventTypes returns every classified event type, for the completeness test.
func allEventTypes() []string {
	out := make([]string, 0, len(catalog))
	for k := range catalog {
		out = append(out, k)
	}
	return out
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/audit/ -run 'TestEveryCatalogEventHasCriticality|TestTierMatchesSpec|TestUnknownEventTypeIsNotClassified' -v`
Expected: PASS (3 tests).

- [ ] **Step 6: Commit**

```bash
git add internal/audit/audit.go internal/audit/catalog.go internal/audit/catalog_test.go
git commit -m "feat(audit): add Logger interface, NopLogger, event catalog with static criticality"
```

---

## Task 2: Hash chain canonical payload and hash

**Files:**
- Create: `internal/audit/hashchain.go`
- Test: `internal/audit/hashchain_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/audit/hashchain_test.go`:

```go
package audit

import (
	"strings"
	"testing"
)

func TestComputeHashFormatAndDeterminism(t *testing.T) {
	rec := record{
		Seq:           1,
		TS:            "2026-06-04T10:00:00Z",
		ActorDeviceID: "DEV1",
		ActorRole:     "admin",
		EventType:     EventCertSign,
		Criticality:   Critical,
		Outcome:       OutcomeAllow,
		Target:        "CN=device,O=sentinel",
		Detail:        `{"role":"operator"}`,
		PrevHash:      "",
	}
	h1 := computeHash(canonicalPayload(rec))
	h2 := computeHash(canonicalPayload(rec))
	if h1 != h2 {
		t.Fatalf("hash not deterministic: %q vs %q", h1, h2)
	}
	if !strings.HasPrefix(h1, "sha256:") {
		t.Fatalf("hash missing sha256: prefix: %q", h1)
	}
	if len(h1) != len("sha256:")+64 {
		t.Fatalf("hash wrong length: %q (len %d)", h1, len(h1))
	}
}

func TestCanonicalDetailHasSortedKeys(t *testing.T) {
	// Two semantically equal detail strings with different key order must
	// canonicalize to the same payload (the store always passes sorted-key JSON,
	// but the canonicalizer must not depend on insertion order of the source).
	a := canonicalDetailJSON(map[string]any{"b": 2, "a": 1})
	b := canonicalDetailJSON(map[string]any{"a": 1, "b": 2})
	if a != b {
		t.Fatalf("canonical detail not order-independent: %q vs %q", a, b)
	}
	if a != `{"a":1,"b":2}` {
		t.Fatalf("canonical detail = %q, want sorted-key JSON", a)
	}
}

func TestEmptyDetailIsEmptyObject(t *testing.T) {
	if got := canonicalDetailJSON(nil); got != "{}" {
		t.Fatalf("nil detail = %q, want {}", got)
	}
	if got := canonicalDetailJSON(map[string]any{}); got != "{}" {
		t.Fatalf("empty detail = %q, want {}", got)
	}
}

func TestAnyFieldChangeChangesHash(t *testing.T) {
	base := record{Seq: 1, TS: "t", ActorDeviceID: "d", ActorRole: "r",
		EventType: "e", Criticality: Routine, Outcome: OutcomeAllow,
		Target: "g", Detail: "{}", PrevHash: ""}
	baseHash := computeHash(canonicalPayload(base))

	mutated := base
	mutated.Target = "g2"
	if computeHash(canonicalPayload(mutated)) == baseHash {
		t.Fatal("changing Target did not change the hash")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/audit/ -run 'TestComputeHash|TestCanonicalDetail|TestEmptyDetail|TestAnyFieldChange' -v`
Expected: FAIL — `undefined: record`, `undefined: computeHash`, `undefined: canonicalPayload`, `undefined: canonicalDetailJSON`.

- [ ] **Step 3: Write the implementation**

Create `internal/audit/hashchain.go`:

```go
package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
)

// record is the fully-resolved row as it is stored and hashed. Field names and
// order here are load-bearing: canonicalPayload concatenates them in exactly
// this order, so changing the order is a breaking change to the chain format.
type record struct {
	Seq           int64
	TS            string // RFC3339Nano UTC
	ActorDeviceID string
	ActorRole     string
	EventType     string
	Criticality   Criticality
	Outcome       Outcome
	Target        string
	Detail        string // canonical JSON, "{}" if empty
	Segment       int64
	PrevHash      string
	Hash          string // filled in by computeHash; not part of the payload
}

// nul is the field separator. Using NUL (0x00) prevents any field value from
// being confused with a separator, since the textual fields cannot contain it
// (JSON encodes control chars, and the other fields are ids/timestamps/hashes).
const nul = "\x00"

// canonicalPayload builds the deterministic byte string that is hashed. Field
// order is fixed (matches §4.1 of the design): seq, ts, actor_device_id,
// actor_role, event_type, criticality, outcome, target, detail, prev_hash.
// Segment and Hash are intentionally excluded: segment is bookkeeping and hash
// is the output.
func canonicalPayload(r record) []byte {
	var b bytes.Buffer
	b.WriteString(strconv.FormatInt(r.Seq, 10))
	b.WriteString(nul)
	b.WriteString(r.TS)
	b.WriteString(nul)
	b.WriteString(r.ActorDeviceID)
	b.WriteString(nul)
	b.WriteString(r.ActorRole)
	b.WriteString(nul)
	b.WriteString(r.EventType)
	b.WriteString(nul)
	b.WriteString(strconv.Itoa(int(r.Criticality)))
	b.WriteString(nul)
	b.WriteString(string(r.Outcome))
	b.WriteString(nul)
	b.WriteString(r.Target)
	b.WriteString(nul)
	b.WriteString(r.Detail)
	b.WriteString(nul)
	b.WriteString(r.PrevHash)
	return b.Bytes()
}

// computeHash returns "sha256:" + hex(SHA-256(payload)).
func computeHash(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// canonicalDetailJSON renders a detail map as JSON with sorted keys, returning
// "{}" for nil/empty. Sorted keys make the stored detail (and thus the hash)
// deterministic across platforms and map-iteration order.
func canonicalDetailJSON(detail map[string]any) string {
	if len(detail) == 0 {
		return "{}"
	}
	keys := make([]string, 0, len(detail))
	for k := range detail {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		b.Write(kb)
		b.WriteByte(':')
		vb, err := json.Marshal(detail[k])
		if err != nil {
			vb = []byte(`null`)
		}
		b.Write(vb)
	}
	b.WriteByte('}')
	return b.String()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/audit/ -run 'TestComputeHash|TestCanonicalDetail|TestEmptyDetail|TestAnyFieldChange' -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/audit/hashchain.go internal/audit/hashchain_test.go
git commit -m "feat(audit): add canonical hash-chain payload and SHA-256 hashing"
```

---

## Task 3: SQLite store — open, schema, 0600 perms, genesis, Append

**Files:**
- Create: `internal/audit/store.go`
- Test: `internal/audit/store_test.go`
- Test: `internal/audit/store_perm_unix_test.go`
- Test: `internal/audit/store_perm_windows_test.go`

- [ ] **Step 1: Write the failing test (open + append + chain links)**

Create `internal/audit/store_test.go`:

```go
package audit

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func newTestLogger(t *testing.T) *SQLiteLogger {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	l, err := Open(Options{DBPath: path, SegmentMax: 10000})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func TestOpenCreatesSchemaAndGenesis(t *testing.T) {
	l := newTestLogger(t)
	var n int
	if err := l.db.QueryRow(`SELECT COUNT(*) FROM audit_meta`).Scan(&n); err != nil {
		t.Fatalf("count meta: %v", err)
	}
	if n != 1 {
		t.Fatalf("audit_meta rows = %d, want 1 (genesis)", n)
	}
}

func TestAppendChainsRecords(t *testing.T) {
	l := newTestLogger(t)
	ctx := WithActor(context.Background(), "DEV1", "admin")
	for i := 0; i < 3; i++ {
		if err := l.Record(ctx, Event{Type: EventCertSign, Outcome: OutcomeAllow, Target: "t"}); err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}
	rows, err := l.db.Query(`SELECT seq, prev_hash, hash FROM audit_log ORDER BY seq`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var prevHash string
	count := 0
	for rows.Next() {
		var seq int64
		var prev, hash string
		if err := rows.Scan(&seq, &prev, &hash); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if prev != prevHash {
			t.Fatalf("seq %d prev_hash = %q, want %q (prior hash)", seq, prev, prevHash)
		}
		prevHash = hash
		count++
	}
	if count != 3 {
		t.Fatalf("rows = %d, want 3", count)
	}
}

func TestAppendStoresActorFromContextNotEvent(t *testing.T) {
	l := newTestLogger(t)
	ctx := WithActor(context.Background(), "REALACTOR", "operator")
	if err := l.Record(ctx, Event{Type: EventExecRun, Outcome: OutcomeAllow, Target: "go"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	var dev, role string
	if err := l.db.QueryRow(`SELECT actor_device_id, actor_role FROM audit_log WHERE seq = 1`).Scan(&dev, &role); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if dev != "REALACTOR" || role != "operator" {
		t.Fatalf("actor = %q/%q, want REALACTOR/operator", dev, role)
	}
}

func TestSystemActorWhenNoContextActor(t *testing.T) {
	l := newTestLogger(t)
	if err := l.Record(context.Background(), Event{Type: EventDaemonStart, Outcome: OutcomeAllow, Target: "self"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	var dev, role string
	if err := l.db.QueryRow(`SELECT actor_device_id, actor_role FROM audit_log WHERE seq = 1`).Scan(&dev, &role); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if dev != "" || role != "system" {
		t.Fatalf("system actor = %q/%q, want \"\"/system", dev, role)
	}
}

var _ = sql.ErrNoRows // keep database/sql import referenced for future use
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/audit/ -run 'TestOpenCreatesSchema|TestAppendChains|TestAppendStoresActor|TestSystemActor' -v`
Expected: FAIL — `undefined: Open`, `undefined: Options`, `undefined: SQLiteLogger`.

- [ ] **Step 3: Write the implementation**

Create `internal/audit/store.go`:

```go
package audit

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

// Options configures the SQLite-backed logger.
type Options struct {
	DBPath        string       // path to audit.db (created 0600 if absent)
	SegmentMax    int          // records per segment before seal; <1 means default
	RetentionDays int          // 0 = keep forever (used by Prune)
	Logger        *slog.Logger // operational slog mirror; defaults to slog.Default()
}

const defaultSegmentMax = 10000

// SQLiteLogger is the tamper-evident, hash-chained audit Logger backed by a
// dedicated SQLite database. Appends are serialized by a process-level mutex so
// the chain has a single writer.
type SQLiteLogger struct {
	db            *sql.DB
	logger        *slog.Logger
	segmentMax    int
	retentionDays int

	mu       sync.Mutex // serializes Append (single-writer chain)
	failures atomic.Int64
	warnOnce sync.Once
}

const schema = `
CREATE TABLE IF NOT EXISTS audit_log (
    seq              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts               TEXT    NOT NULL,
    actor_device_id  TEXT    NOT NULL,
    actor_role       TEXT    NOT NULL,
    event_type       TEXT    NOT NULL,
    criticality      INTEGER NOT NULL,
    outcome          TEXT    NOT NULL,
    target           TEXT    NOT NULL,
    detail           TEXT    NOT NULL,
    segment          INTEGER NOT NULL,
    prev_hash        TEXT    NOT NULL,
    hash             TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ts      ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_type    ON audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_actor   ON audit_log(actor_device_id);
CREATE INDEX IF NOT EXISTS idx_audit_segment ON audit_log(segment);

CREATE TABLE IF NOT EXISTS audit_meta (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    genesis_hash TEXT NOT NULL,
    last_seq     INTEGER NOT NULL,
    last_hash    TEXT NOT NULL,
    segment      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_segments (
    segment_id  INTEGER PRIMARY KEY,
    first_seq   INTEGER NOT NULL,
    last_seq    INTEGER NOT NULL,
    anchor_hash TEXT NOT NULL,
    sealed_at   TEXT NOT NULL
);
`

// Open opens (creating if absent, with 0600 perms) the audit database, applies
// the schema, and seeds the single-row audit_meta genesis if it is empty.
func Open(opts Options) (*SQLiteLogger, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.SegmentMax < 1 {
		opts.SegmentMax = defaultSegmentMax
	}

	// Pre-create the file with 0600 so the DB never exists with looser perms,
	// even briefly. modernc.org/sqlite opens an existing file rather than
	// creating a new one with default mode.
	if _, statErr := os.Stat(opts.DBPath); os.IsNotExist(statErr) {
		f, err := os.OpenFile(opts.DBPath, os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("audit: create db file: %w", err)
		}
		_ = f.Close()
	}

	db, err := sql.Open("sqlite", opts.DBPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("audit: open db: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("audit: apply schema: %w", err)
	}

	l := &SQLiteLogger{
		db:            db,
		logger:        opts.Logger,
		segmentMax:    opts.SegmentMax,
		retentionDays: opts.RetentionDays,
	}
	if err := l.ensureGenesis(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return l, nil
}

// ensureGenesis seeds the audit_meta row on a fresh database. The genesis hash
// is the chain anchor; the first appended record uses prev_hash = "".
func (l *SQLiteLogger) ensureGenesis() error {
	var n int
	if err := l.db.QueryRow(`SELECT COUNT(*) FROM audit_meta`).Scan(&n); err != nil {
		return fmt.Errorf("audit: count meta: %w", err)
	}
	if n > 0 {
		return nil
	}
	genesis := computeHash([]byte("sentinel-audit-genesis"))
	_, err := l.db.Exec(
		`INSERT INTO audit_meta (id, genesis_hash, last_seq, last_hash, segment)
		 VALUES (1, ?, 0, ?, 0)`,
		genesis, genesis,
	)
	if err != nil {
		return fmt.Errorf("audit: seed genesis: %w", err)
	}
	return nil
}

// Record builds a full record from the event + context actor, redacts the
// detail, and appends it. Errors are returned to the caller, which acts on them
// per the event's tier (see Record callers in cmd/serve.go and the interceptor).
func (l *SQLiteLogger) Record(ctx context.Context, ev Event) error {
	crit, ok := CriticalityOf(ev.Type)
	if !ok {
		// An unclassified event is a programming error, but we must not drop it
		// silently. Treat it as Critical so the gap surfaces loudly.
		crit = Critical
		l.logger.Error("audit: unclassified event type recorded as critical", "type", ev.Type)
	}
	act := actorFromContext(ctx)
	detail := canonicalDetailJSON(redactDetail(ev.Detail))

	rec := record{
		TS:            time.Now().UTC().Format(time.RFC3339Nano),
		ActorDeviceID: act.deviceID,
		ActorRole:     act.role,
		EventType:     ev.Type,
		Criticality:   crit,
		Outcome:       ev.Outcome,
		Target:        ev.Target,
		Detail:        detail,
	}

	if err := l.append(rec); err != nil {
		l.failures.Add(1)
		// Mirror to the operational stream so a write failure is always visible
		// even when the caller's tier is routine.
		l.warnOnce.Do(func() {
			l.logger.Warn("audit: write failure (subsequent failures suppressed)",
				"type", ev.Type, "error", err)
		})
		return fmt.Errorf("audit: record %s: %w", ev.Type, err)
	}

	// Parallel, non-authoritative operational line for routine observability.
	l.logger.Info("audit", "type", ev.Type, "outcome", ev.Outcome,
		"actor", act.deviceID, "role", act.role, "target", ev.Target)
	return nil
}

// append inserts one record and updates audit_meta in a single transaction under
// the single-writer mutex. It computes seq, prev_hash, segment, and hash from
// the current meta state.
func (l *SQLiteLogger) append(rec record) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	tx, err := l.db.Begin()
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var lastSeq, segment int64
	var lastHash string
	if err := tx.QueryRow(
		`SELECT last_seq, last_hash, segment FROM audit_meta WHERE id = 1`,
	).Scan(&lastSeq, &lastHash, &segment); err != nil {
		return fmt.Errorf("read meta: %w", err)
	}

	rec.Seq = lastSeq + 1
	rec.PrevHash = lastHash
	rec.Segment = segment
	rec.Hash = computeHash(canonicalPayload(rec))

	if _, err := tx.Exec(
		`INSERT INTO audit_log
		 (seq, ts, actor_device_id, actor_role, event_type, criticality, outcome, target, detail, segment, prev_hash, hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.Seq, rec.TS, rec.ActorDeviceID, rec.ActorRole, rec.EventType,
		int(rec.Criticality), string(rec.Outcome), rec.Target, rec.Detail,
		rec.Segment, rec.PrevHash, rec.Hash,
	); err != nil {
		return fmt.Errorf("insert: %w", err)
	}

	if _, err := tx.Exec(
		`UPDATE audit_meta SET last_seq = ?, last_hash = ? WHERE id = 1`,
		rec.Seq, rec.Hash,
	); err != nil {
		return fmt.Errorf("update meta: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}

	// Seal the segment after commit if it has reached the bound. Sealing failures
	// are non-fatal to the just-committed append (the record is durable); they
	// are logged and retried on the next append.
	if rec.Seq%int64(l.segmentMax) == 0 {
		if err := l.sealSegment(rec.Segment, rec.Hash); err != nil {
			l.logger.Warn("audit: seal segment failed", "segment", rec.Segment, "error", err)
		}
	}
	return nil
}

// WriteFailures returns the count of audit write failures since process start.
// It backs the audit_write_failures_total metric.
func (l *SQLiteLogger) WriteFailures() int64 { return l.failures.Load() }

// Close closes the underlying database.
func (l *SQLiteLogger) Close() error {
	if err := l.db.Close(); err != nil {
		return fmt.Errorf("audit: close: %w", err)
	}
	return nil
}
```

NOTE: `redactDetail` (Task 5) and `sealSegment` (Task 6) are referenced here. To keep this task compiling on its own, add temporary stubs at the bottom of `store.go` now and replace them in their tasks:

```go
// --- temporary stubs, replaced in Task 5 (redact) and Task 6 (segment) ---

func redactDetail(d map[string]any) map[string]any { return d }

func (l *SQLiteLogger) sealSegment(_ int64, _ string) error { return nil }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/audit/ -run 'TestOpenCreatesSchema|TestAppendChains|TestAppendStoresActor|TestSystemActor' -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Write the cross-platform permission tests**

Create `internal/audit/store_perm_unix_test.go`:

```go
//go:build !windows

package audit

import (
	"path/filepath"
	"testing"
)

func TestDBFileIs0600Unix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	l, err := Open(Options{DBPath: path})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = l.Close() }()

	fi, err := statFile(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("db perms = %o, want 600", perm)
	}
}
```

Create `internal/audit/store_perm_windows_test.go`:

```go
//go:build windows

package audit

import (
	"path/filepath"
	"testing"
)

// On Windows there are no Unix mode bits; we assert the file exists and is
// readable/writable by the owner. ACL hardening is handled by the data-dir
// creation (datadir.Root, 0700-equivalent) and is out of scope for this unit.
func TestDBFileCreatedWindows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	l, err := Open(Options{DBPath: path})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = l.Close() }()

	if _, err := statFile(path); err != nil {
		t.Fatalf("stat: %v", err)
	}
}
```

Add the shared `statFile` helper to `internal/audit/store.go`:

```go
// statFile is a thin wrapper so permission tests can stat the db path without
// re-importing os in test files that build on only one platform.
func statFile(path string) (os.FileInfo, error) { return os.Stat(path) }
```

- [ ] **Step 6: Run the permission test for this platform**

Run: `go test ./internal/audit/ -run 'TestDBFile' -v`
Expected: PASS (the test for the current OS; the other is excluded by build tag).

- [ ] **Step 7: Commit**

```bash
git add internal/audit/store.go internal/audit/store_test.go internal/audit/store_perm_unix_test.go internal/audit/store_perm_windows_test.go
git commit -m "feat(audit): add SQLite store with 0600 perms, genesis, mutex-serialized append"
```

---

## Task 4: Verification — edit / reorder / truncation detection

**Files:**
- Create: `internal/audit/verify.go`
- Test: `internal/audit/verify_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/audit/verify_test.go`:

```go
package audit

import (
	"context"
	"testing"
)

func appendN(t *testing.T, l *SQLiteLogger, n int) {
	t.Helper()
	ctx := WithActor(context.Background(), "DEV", "admin")
	for i := 0; i < n; i++ {
		if err := l.Record(ctx, Event{Type: EventExecRun, Outcome: OutcomeAllow, Target: "go"}); err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}
}

func TestVerifyCleanChain(t *testing.T) {
	l := newTestLogger(t)
	appendN(t, l, 5)
	if brk, err := l.Verify(0); err != nil {
		t.Fatalf("Verify err: %v", err)
	} else if brk != nil {
		t.Fatalf("clean chain reported break: %+v", brk)
	}
}

func TestVerifyDetectsEdit(t *testing.T) {
	l := newTestLogger(t)
	appendN(t, l, 5)
	// Tamper: change a stored detail without recomputing the hash.
	if _, err := l.db.Exec(`UPDATE audit_log SET detail = '{"x":1}' WHERE seq = 3`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	brk, err := l.Verify(0)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if brk == nil || brk.Kind != BreakEdit || brk.Seq != 3 {
		t.Fatalf("got %+v, want edit at seq 3", brk)
	}
}

func TestVerifyDetectsReorder(t *testing.T) {
	l := newTestLogger(t)
	appendN(t, l, 5)
	// Tamper: corrupt prev_hash linkage at seq 4 (reorder/forgery signal).
	if _, err := l.db.Exec(`UPDATE audit_log SET prev_hash = 'sha256:deadbeef' WHERE seq = 4`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	brk, err := l.Verify(0)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	// The edited prev_hash both breaks this record's own hash recomputation and
	// the link to seq-1; the first detected break is at seq 4.
	if brk == nil || brk.Seq != 4 {
		t.Fatalf("got %+v, want break at seq 4", brk)
	}
}

func TestVerifyDetectsTruncation(t *testing.T) {
	l := newTestLogger(t)
	appendN(t, l, 5)
	// Tamper: delete the last row but leave meta claiming last_seq = 5.
	if _, err := l.db.Exec(`DELETE FROM audit_log WHERE seq = 5`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	brk, err := l.Verify(0)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if brk == nil || brk.Kind != BreakTruncation {
		t.Fatalf("got %+v, want truncation", brk)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/audit/ -run TestVerify -v`
Expected: FAIL — `undefined: (*SQLiteLogger).Verify`, `undefined: BreakEdit`, `undefined: BreakTruncation`.

- [ ] **Step 3: Write the implementation**

Create `internal/audit/verify.go`:

```go
package audit

import "fmt"

// BreakKind classifies a detected chain break.
type BreakKind string

const (
	BreakEdit       BreakKind = "edit"          // recomputed hash != stored hash
	BreakReorder    BreakKind = "reorder"       // prev_hash != prior record's hash
	BreakTruncation BreakKind = "truncation"    // meta last_seq > max(seq) present
)

// VerifyBreak describes the first detected integrity violation.
type VerifyBreak struct {
	Seq      int64
	Kind     BreakKind
	Expected string
	Actual   string
}

func (b *VerifyBreak) Error() string {
	return fmt.Sprintf("audit break: %s at seq %d (expected %q, actual %q)",
		b.Kind, b.Seq, b.Expected, b.Actual)
}

// Verify walks the chain from genesis (fromSegment == 0) or from the anchor of
// the given sealed segment, returning the FIRST break or nil if intact. A
// non-nil error is an operational failure (e.g. db read), distinct from a
// detected break.
func (l *SQLiteLogger) Verify(fromSegment int) (*VerifyBreak, error) {
	// Determine the starting prev_hash. From genesis the first record's
	// prev_hash must be "". From a sealed segment, the start anchor is that
	// segment's anchor_hash and we begin at its first_seq.
	prevHash := ""
	var startSeq int64 = 1

	if fromSegment > 0 {
		var firstSeq int64
		var anchor string
		err := l.db.QueryRow(
			`SELECT first_seq, anchor_hash FROM audit_segments WHERE segment_id = ?`,
			fromSegment,
		).Scan(&firstSeq, &anchor)
		if err != nil {
			return nil, fmt.Errorf("audit: load segment %d anchor: %w", fromSegment, err)
		}
		startSeq = firstSeq
		// The anchor is the terminal hash of the PRIOR segment, i.e. the
		// prev_hash the first retained record must carry.
		prevHash = anchor
	}

	rows, err := l.db.Query(
		`SELECT seq, ts, actor_device_id, actor_role, event_type, criticality, outcome, target, detail, segment, prev_hash, hash
		 FROM audit_log WHERE seq >= ? ORDER BY seq`, startSeq,
	)
	if err != nil {
		return nil, fmt.Errorf("audit: scan chain: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var lastSeq int64
	for rows.Next() {
		var r record
		var crit int
		if err := rows.Scan(
			&r.Seq, &r.TS, &r.ActorDeviceID, &r.ActorRole, &r.EventType,
			&crit, &r.Outcome, &r.Target, &r.Detail, &r.Segment, &r.PrevHash, &r.Hash,
		); err != nil {
			return nil, fmt.Errorf("audit: scan record: %w", err)
		}
		r.Criticality = Criticality(crit)

		// Reorder/forgery: this record's prev_hash must equal the running hash.
		if r.PrevHash != prevHash {
			return &VerifyBreak{Seq: r.Seq, Kind: BreakReorder, Expected: prevHash, Actual: r.PrevHash}, nil
		}
		// Edit: recomputed hash must equal the stored hash.
		want := computeHash(canonicalPayload(r))
		if want != r.Hash {
			return &VerifyBreak{Seq: r.Seq, Kind: BreakEdit, Expected: want, Actual: r.Hash}, nil
		}
		prevHash = r.Hash
		lastSeq = r.Seq
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: iterate chain: %w", err)
	}

	// Truncation: meta claims a higher last_seq than the rows present.
	var metaLastSeq int64
	if err := l.db.QueryRow(`SELECT last_seq FROM audit_meta WHERE id = 1`).Scan(&metaLastSeq); err != nil {
		return nil, fmt.Errorf("audit: read meta last_seq: %w", err)
	}
	if metaLastSeq > lastSeq {
		return &VerifyBreak{
			Seq:      lastSeq + 1,
			Kind:     BreakTruncation,
			Expected: fmt.Sprintf("seq up to %d", metaLastSeq),
			Actual:   fmt.Sprintf("max present %d", lastSeq),
		}, nil
	}
	return nil, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/audit/ -run TestVerify -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/audit/verify.go internal/audit/verify_test.go
git commit -m "feat(audit): add chain verification detecting edit, reorder, truncation"
```

---

## Task 5: Detail redaction allowlist

**Files:**
- Modify: `internal/audit/store.go` (remove the `redactDetail` stub)
- Create: `internal/audit/redact.go`
- Test: `internal/audit/redact_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/audit/redact_test.go`:

```go
package audit

import "testing"

func TestRedactKeepsAllowlistedKeys(t *testing.T) {
	in := map[string]any{
		"command": "go",
		"argv":    []string{"go", "build"},
		"role":    "operator",
		"path":    "/x/y",
	}
	out := redactDetail(in)
	for _, k := range []string{"command", "argv", "role", "path"} {
		if _, ok := out[k]; !ok {
			t.Errorf("allowlisted key %q was dropped", k)
		}
	}
}

func TestRedactDropsUnknownKeys(t *testing.T) {
	in := map[string]any{"command": "go", "wat": "should-drop"}
	out := redactDetail(in)
	if _, ok := out["wat"]; ok {
		t.Error("non-allowlisted key was retained")
	}
}

func TestRedactReplacesSensitiveKeys(t *testing.T) {
	in := map[string]any{"private_key": "MII...", "password": "hunter2", "token": "abc"}
	out := redactDetail(in)
	for _, k := range []string{"private_key", "password", "token"} {
		v, ok := out[k]
		if !ok {
			t.Errorf("sensitive key %q dropped entirely; want redaction marker", k)
			continue
		}
		if v != "[redacted]" {
			t.Errorf("sensitive key %q = %v, want [redacted]", k, v)
		}
	}
}

func TestRedactNilIsNil(t *testing.T) {
	if out := redactDetail(nil); len(out) != 0 {
		t.Fatalf("nil detail produced %v", out)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/audit/ -run TestRedact -v`
Expected: FAIL — `TestRedactDropsUnknownKeys` fails because the stub returns the input unchanged (the `wat` key survives).

- [ ] **Step 3: Remove the stub and add the real implementation**

In `internal/audit/store.go`, delete these stub lines:

```go
func redactDetail(d map[string]any) map[string]any { return d }
```

Create `internal/audit/redact.go`:

```go
package audit

// allowedDetailKeys is the allowlist of Detail keys that may be stored. Any key
// not present is dropped, so a caller cannot accidentally persist arbitrary
// (possibly sensitive) context. Keep this list curated and minimal.
var allowedDetailKeys = map[string]struct{}{
	"command":     {},
	"argv":        {},
	"cwd":         {},
	"path":        {},
	"role":        {},
	"method":      {},
	"peer":        {},
	"device_id":   {},
	"subject":     {},
	"fingerprint": {},
	"reason":      {},
	"segment":     {},
	"binary":      {},
}

// sensitiveDetailKeys are keys that, if present, are replaced with a redaction
// marker rather than dropped — so the record shows the field existed but never
// stores its value.
var sensitiveDetailKeys = map[string]struct{}{
	"private_key": {},
	"key":         {},
	"password":    {},
	"secret":      {},
	"token":       {},
	"env":         {},
}

const redactedMarker = "[redacted]"

// redactDetail returns a copy of detail containing only allowlisted keys, with
// any sensitive key replaced by the redaction marker. nil in yields nil out.
func redactDetail(detail map[string]any) map[string]any {
	if len(detail) == 0 {
		return nil
	}
	out := make(map[string]any, len(detail))
	for k, v := range detail {
		if _, sensitive := sensitiveDetailKeys[k]; sensitive {
			out[k] = redactedMarker
			continue
		}
		if _, ok := allowedDetailKeys[k]; ok {
			out[k] = v
		}
		// else: silently dropped (not on the allowlist).
	}
	return out
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/audit/ -run TestRedact -v`
Expected: PASS (4 tests). Also run `go test ./internal/audit/ -v` to confirm no regressions from removing the stub.

- [ ] **Step 5: Commit**

```bash
git add internal/audit/redact.go internal/audit/redact_test.go internal/audit/store.go
git commit -m "feat(audit): redact Detail to an allowlist, mask sensitive keys"
```

---

## Task 6: Sealed segments and retention prune

**Files:**
- Modify: `internal/audit/store.go` (remove the `sealSegment` stub)
- Create: `internal/audit/segment.go`
- Test: `internal/audit/segment_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/audit/segment_test.go`:

```go
package audit

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func newSmallSegmentLogger(t *testing.T) *SQLiteLogger {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	l, err := Open(Options{DBPath: path, SegmentMax: 3})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func TestSegmentSealsAtBound(t *testing.T) {
	l := newSmallSegmentLogger(t)
	appendN(t, l, 3) // exactly fills segment 0 -> seals it
	var sealed int
	if err := l.db.QueryRow(`SELECT COUNT(*) FROM audit_segments WHERE segment_id = 0`).Scan(&sealed); err != nil {
		t.Fatalf("count segments: %v", err)
	}
	if sealed != 1 {
		t.Fatalf("segment 0 sealed rows = %d, want 1", sealed)
	}
	// A new segment must have started so the next append lands in segment 1.
	var metaSeg int64
	if err := l.db.QueryRow(`SELECT segment FROM audit_meta WHERE id = 1`).Scan(&metaSeg); err != nil {
		t.Fatalf("read meta segment: %v", err)
	}
	if metaSeg != 1 {
		t.Fatalf("meta segment = %d, want 1", metaSeg)
	}
}

func TestChainUnbrokenAcrossSeam(t *testing.T) {
	l := newSmallSegmentLogger(t)
	appendN(t, l, 5) // seals segment 0, lands 2 records in segment 1
	if brk, err := l.Verify(0); err != nil {
		t.Fatalf("Verify err: %v", err)
	} else if brk != nil {
		t.Fatalf("seam broke the chain: %+v", brk)
	}
}

func TestPruneDropsOldSegmentAndChainStillVerifies(t *testing.T) {
	l := newSmallSegmentLogger(t)
	appendN(t, l, 9) // segments 0,1,2 sealed (3 each)
	// Backdate segment 0 so the retention window catches it.
	old := time.Now().UTC().Add(-100 * 24 * time.Hour).Format(time.RFC3339Nano)
	if _, err := l.db.Exec(`UPDATE audit_segments SET sealed_at = ? WHERE segment_id = 0`, old); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	pruned, err := l.Prune(context.Background(), 90)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if pruned != 1 {
		t.Fatalf("pruned = %d, want 1", pruned)
	}
	// Segment 0 rows are gone.
	var remaining int
	if err := l.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE segment = 0`).Scan(&remaining); err != nil {
		t.Fatalf("count: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("segment 0 rows remaining = %d, want 0", remaining)
	}
	// The retained chain must still verify starting from the new oldest segment.
	if brk, err := l.Verify(1); err != nil {
		t.Fatalf("Verify(1) err: %v", err)
	} else if brk != nil {
		t.Fatalf("retained chain broke after prune: %+v", brk)
	}
}

func TestPruneZeroKeepsForever(t *testing.T) {
	l := newSmallSegmentLogger(t)
	appendN(t, l, 9)
	pruned, err := l.Prune(context.Background(), 0)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if pruned != 0 {
		t.Fatalf("retention 0 pruned %d segments, want 0 (keep forever)", pruned)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/audit/ -run 'TestSegment|TestChainUnbroken|TestPrune' -v`
Expected: FAIL — `undefined: (*SQLiteLogger).Prune`, and `TestSegmentSealsAtBound` fails because the `sealSegment` stub writes no `audit_segments` row and never advances the segment.

- [ ] **Step 3: Remove the stub and add the real implementation**

In `internal/audit/store.go`, delete the stub line:

```go
func (l *SQLiteLogger) sealSegment(_ int64, _ string) error { return nil }
```

Create `internal/audit/segment.go`:

```go
package audit

import (
	"context"
	"fmt"
	"time"
)

// sealSegment records a sealed-segment row anchoring the segment's terminal hash
// and advances audit_meta.segment so subsequent appends land in a new segment.
// The new segment's first record still chains off the sealed segment's terminal
// hash (append reads last_hash from meta, which is unchanged here), so the chain
// is unbroken across the seam.
//
// Called from append while the single-writer mutex is held, so it does not take
// the lock itself.
func (l *SQLiteLogger) sealSegment(segment int64, terminalHash string) error {
	tx, err := l.db.Begin()
	if err != nil {
		return fmt.Errorf("seal: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var firstSeq, lastSeq int64
	if err := tx.QueryRow(
		`SELECT MIN(seq), MAX(seq) FROM audit_log WHERE segment = ?`, segment,
	).Scan(&firstSeq, &lastSeq); err != nil {
		return fmt.Errorf("seal: range: %w", err)
	}

	if _, err := tx.Exec(
		`INSERT OR REPLACE INTO audit_segments (segment_id, first_seq, last_seq, anchor_hash, sealed_at)
		 VALUES (?, ?, ?, ?, ?)`,
		segment, firstSeq, lastSeq, terminalHash, time.Now().UTC().Format(time.RFC3339Nano),
	); err != nil {
		return fmt.Errorf("seal: insert segment: %w", err)
	}

	if _, err := tx.Exec(
		`UPDATE audit_meta SET segment = segment + 1 WHERE id = 1`,
	); err != nil {
		return fmt.Errorf("seal: advance segment: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("seal: commit: %w", err)
	}
	return nil
}

// Prune drops whole sealed segments older than retentionDays, returning the
// number of segments pruned. retentionDays == 0 keeps everything. Pruning is
// itself a routine audit event (audit.prune) recorded per dropped segment.
//
// The oldest RETAINED sealed segment's anchor becomes the new verification start
// point (callers pass its id to Verify). The live (unsealed) segment is never
// pruned.
func (l *SQLiteLogger) Prune(ctx context.Context, retentionDays int) (int, error) {
	if retentionDays <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour).Format(time.RFC3339Nano)

	rows, err := l.db.Query(
		`SELECT segment_id FROM audit_segments WHERE sealed_at < ? ORDER BY segment_id`, cutoff,
	)
	if err != nil {
		return 0, fmt.Errorf("audit: prune scan: %w", err)
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("audit: prune scan id: %w", err)
		}
		ids = append(ids, id)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("audit: prune iterate: %w", err)
	}

	pruned := 0
	for _, id := range ids {
		l.mu.Lock()
		tx, err := l.db.Begin()
		if err != nil {
			l.mu.Unlock()
			return pruned, fmt.Errorf("audit: prune begin: %w", err)
		}
		if _, err := tx.Exec(`DELETE FROM audit_log WHERE segment = ?`, id); err != nil {
			_ = tx.Rollback()
			l.mu.Unlock()
			return pruned, fmt.Errorf("audit: prune delete log: %w", err)
		}
		if _, err := tx.Exec(`DELETE FROM audit_segments WHERE segment_id = ?`, id); err != nil {
			_ = tx.Rollback()
			l.mu.Unlock()
			return pruned, fmt.Errorf("audit: prune delete segment: %w", err)
		}
		if err := tx.Commit(); err != nil {
			l.mu.Unlock()
			return pruned, fmt.Errorf("audit: prune commit: %w", err)
		}
		l.mu.Unlock()
		pruned++

		// Record the prune as a routine event (best-effort; a failure here must
		// not undo the prune).
		_ = l.Record(ctx, Event{
			Type:    EventAuditPrune,
			Outcome: OutcomeAllow,
			Target:  fmt.Sprintf("segment %d", id),
			Detail:  map[string]any{"segment": id},
		})
	}
	return pruned, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/audit/ -run 'TestSegment|TestChainUnbroken|TestPrune' -v`
Expected: PASS (4 tests). Also run `go test ./internal/audit/ -v` for the full package.

- [ ] **Step 5: Commit**

```bash
git add internal/audit/segment.go internal/audit/segment_test.go internal/audit/store.go
git commit -m "feat(audit): seal segments at bound and prune whole old segments on retention"
```

---

## Task 7: Read-only query/tail/export helpers

**Files:**
- Create: `internal/audit/query.go`
- Test: `internal/audit/query_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/audit/query_test.go`:

```go
package audit

import (
	"context"
	"strings"
	"testing"
)

func TestTailReturnsMostRecentInOrder(t *testing.T) {
	l := newTestLogger(t)
	ctx := WithActor(context.Background(), "DEV", "admin")
	for _, et := range []string{EventCertSign, EventExecRun, EventRBACDeny} {
		if err := l.Record(ctx, Event{Type: et, Outcome: OutcomeAllow, Target: "t"}); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	got, err := l.Tail(Filter{Limit: 2})
	if err != nil {
		t.Fatalf("Tail: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("tail len = %d, want 2", len(got))
	}
	// Ascending by seq within the tail window: the last two recorded.
	if got[0].EventType != EventExecRun || got[1].EventType != EventRBACDeny {
		t.Fatalf("tail order = %s,%s; want exec.run,rbac.deny", got[0].EventType, got[1].EventType)
	}
}

func TestQueryFiltersByTypeAndOutcome(t *testing.T) {
	l := newTestLogger(t)
	ctx := WithActor(context.Background(), "DEV", "admin")
	_ = l.Record(ctx, Event{Type: EventRBACDeny, Outcome: OutcomeDeny, Target: "a"})
	_ = l.Record(ctx, Event{Type: EventExecRun, Outcome: OutcomeAllow, Target: "b"})

	got, err := l.Query(Filter{EventType: EventRBACDeny, Outcome: OutcomeDeny})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 || got[0].EventType != EventRBACDeny {
		t.Fatalf("query = %+v, want one rbac.deny", got)
	}
}

func TestExportJSONContainsRecords(t *testing.T) {
	l := newTestLogger(t)
	ctx := WithActor(context.Background(), "DEV", "admin")
	_ = l.Record(ctx, Event{Type: EventCertSign, Outcome: OutcomeAllow, Target: "cn=x"})

	var sb strings.Builder
	if err := l.Export(&sb, "json", Filter{}); err != nil {
		t.Fatalf("Export json: %v", err)
	}
	if !strings.Contains(sb.String(), "cert.sign") {
		t.Fatalf("json export missing event: %s", sb.String())
	}
}

func TestExportCSVHasHeader(t *testing.T) {
	l := newTestLogger(t)
	ctx := WithActor(context.Background(), "DEV", "admin")
	_ = l.Record(ctx, Event{Type: EventExecRun, Outcome: OutcomeAllow, Target: "go"})

	var sb strings.Builder
	if err := l.Export(&sb, "csv", Filter{}); err != nil {
		t.Fatalf("Export csv: %v", err)
	}
	if !strings.HasPrefix(sb.String(), "seq,ts,actor_device_id,actor_role,event_type,outcome,target") {
		t.Fatalf("csv missing/incorrect header: %q", sb.String())
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/audit/ -run 'TestTail|TestQuery|TestExport' -v`
Expected: FAIL — `undefined: Filter`, `undefined: (*SQLiteLogger).Tail`, `undefined: (*SQLiteLogger).Query`, `undefined: (*SQLiteLogger).Export`.

- [ ] **Step 3: Write the implementation**

Create `internal/audit/query.go`:

```go
package audit

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
)

// Filter narrows tail/query/export results. Zero values mean "no constraint".
type Filter struct {
	Since     string  // RFC3339 lower bound (inclusive) on ts
	Until     string  // RFC3339 upper bound (inclusive) on ts
	EventType string  // exact event_type
	Actor     string  // exact actor_device_id
	Outcome   Outcome // exact outcome
	Limit     int     // 0 = no limit (Query); Tail uses it as the tail window
}

// Row is a read-only projection of a stored audit record for the CLI.
type Row struct {
	Seq           int64  `json:"seq"`
	TS            string `json:"ts"`
	ActorDeviceID string `json:"actor_device_id"`
	ActorRole     string `json:"actor_role"`
	EventType     string `json:"event_type"`
	Outcome       string `json:"outcome"`
	Target        string `json:"target"`
	Detail        string `json:"detail"`
	Segment       int64  `json:"segment"`
}

func (f Filter) where() (string, []any) {
	clause := " WHERE 1=1"
	var args []any
	if f.Since != "" {
		clause += " AND ts >= ?"
		args = append(args, f.Since)
	}
	if f.Until != "" {
		clause += " AND ts <= ?"
		args = append(args, f.Until)
	}
	if f.EventType != "" {
		clause += " AND event_type = ?"
		args = append(args, f.EventType)
	}
	if f.Actor != "" {
		clause += " AND actor_device_id = ?"
		args = append(args, f.Actor)
	}
	if f.Outcome != "" {
		clause += " AND outcome = ?"
		args = append(args, string(f.Outcome))
	}
	return clause, args
}

const selectCols = `seq, ts, actor_device_id, actor_role, event_type, outcome, target, detail, segment`

func (l *SQLiteLogger) scanRows(query string, args []any) ([]Row, error) {
	rows, err := l.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Row
	for rows.Next() {
		var r Row
		if err := rows.Scan(&r.Seq, &r.TS, &r.ActorDeviceID, &r.ActorRole,
			&r.EventType, &r.Outcome, &r.Target, &r.Detail, &r.Segment); err != nil {
			return nil, fmt.Errorf("audit: scan row: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: iterate rows: %w", err)
	}
	return out, nil
}

// Query returns records matching the filter in ascending seq order.
func (l *SQLiteLogger) Query(f Filter) ([]Row, error) {
	where, args := f.where()
	q := `SELECT ` + selectCols + ` FROM audit_log` + where + ` ORDER BY seq`
	if f.Limit > 0 {
		q += ` LIMIT ?`
		args = append(args, f.Limit)
	}
	return l.scanRows(q, args)
}

// Tail returns the most recent records matching the filter, in ascending seq
// order (so the newest is last, like `tail`).
func (l *SQLiteLogger) Tail(f Filter) ([]Row, error) {
	where, args := f.where()
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	// Inner query takes the newest N by descending seq; the outer re-sorts
	// ascending for display.
	q := `SELECT ` + selectCols + ` FROM (
		SELECT ` + selectCols + ` FROM audit_log` + where + ` ORDER BY seq DESC LIMIT ?
	) ORDER BY seq`
	args = append(args, limit)
	return l.scanRows(q, args)
}

// Export writes filtered records to w in the given format ("json" or "csv").
func (l *SQLiteLogger) Export(w io.Writer, format string, f Filter) error {
	rows, err := l.Query(f)
	if err != nil {
		return err
	}
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rows); err != nil {
			return fmt.Errorf("audit: export json: %w", err)
		}
		return nil
	case "csv":
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{"seq", "ts", "actor_device_id", "actor_role", "event_type", "outcome", "target", "detail", "segment"}); err != nil {
			return fmt.Errorf("audit: export csv header: %w", err)
		}
		for _, r := range rows {
			if err := cw.Write([]string{
				strconv.FormatInt(r.Seq, 10), r.TS, r.ActorDeviceID, r.ActorRole,
				r.EventType, r.Outcome, r.Target, r.Detail, strconv.FormatInt(r.Segment, 10),
			}); err != nil {
				return fmt.Errorf("audit: export csv row: %w", err)
			}
		}
		cw.Flush()
		if err := cw.Error(); err != nil {
			return fmt.Errorf("audit: export csv flush: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("audit: unknown export format %q", format)
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/audit/ -run 'TestTail|TestQuery|TestExport' -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/audit/query.go internal/audit/query_test.go
git commit -m "feat(audit): add read-only tail/query/export helpers for the CLI"
```

---

## Task 8: Settings — AuditConfig + v2→v3 migration

**Files:**
- Modify: `internal/settings/settings.go`
- Test: `internal/settings/settings_audit_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/settings/settings_audit_test.go`:

```go
package settings

import "testing"

func TestCurrentConfigVersionIsThree(t *testing.T) {
	if CurrentConfigVersion != 3 {
		t.Fatalf("CurrentConfigVersion = %d, want 3", CurrentConfigVersion)
	}
}

func TestDefaultConfigHasAuditDefaults(t *testing.T) {
	c := DefaultConfig()
	if !c.Audit.Enabled {
		t.Error("audit should default enabled")
	}
	if c.Audit.RetentionDays != 90 {
		t.Errorf("audit retention_days default = %d, want 90", c.Audit.RetentionDays)
	}
	if c.Audit.SegmentMax != 10000 {
		t.Errorf("audit segment_max default = %d, want 10000", c.Audit.SegmentMax)
	}
}

func TestValidateRejectsBadAudit(t *testing.T) {
	c := DefaultConfig()
	c.Audit.RetentionDays = -1
	if err := c.Validate(); err == nil {
		t.Error("expected error for negative retention_days")
	}
	c = DefaultConfig()
	c.Audit.SegmentMax = 0
	if err := c.Validate(); err == nil {
		t.Error("expected error for segment_max < 1")
	}
}

func TestMigrateV2ToV3BumpsVersion(t *testing.T) {
	c := DefaultConfig()
	c.Version = 2
	changed := c.Migrate(2)
	if !changed {
		t.Error("Migrate(2) should report a change")
	}
	if c.Version != 3 {
		t.Errorf("post-migrate version = %d, want 3", c.Version)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/settings/ -run 'TestCurrentConfigVersionIsThree|TestDefaultConfigHasAuditDefaults|TestValidateRejectsBadAudit|TestMigrateV2ToV3' -v`
Expected: FAIL — `CurrentConfigVersion = 2, want 3`, and `c.Audit` undefined (build error).

- [ ] **Step 3: Add the AuditConfig type and wire it**

In `internal/settings/settings.go`, bump the version constant:

```go
const CurrentConfigVersion = 3
```

Add `Audit` to the `Config` struct (alongside `Confine`):

```go
	Confine   ConfineConfig   `yaml:"confine"`
	Audit     AuditConfig     `yaml:"audit"`
```

Add the type and its defaults (place near `ConfineConfig` / `defaultConfineConfig`):

```go
// AuditConfig controls the security audit log (Phase 3.1).
type AuditConfig struct {
	Enabled       bool   `yaml:"enabled"`
	DBPath        string `yaml:"db_path"`        // empty = datadir default (audit.db)
	RetentionDays int    `yaml:"retention_days"` // 0 = keep forever
	SegmentMax    int    `yaml:"segment_max"`    // records per segment before seal
}

// defaultAuditConfig is the single source of truth for audit defaults, shared by
// DefaultConfig so the two cannot drift.
func defaultAuditConfig() AuditConfig {
	return AuditConfig{
		Enabled:       true,
		DBPath:        "",
		RetentionDays: 90,
		SegmentMax:    10000,
	}
}
```

In `DefaultConfig`, add the audit block to the returned struct (after `Confine: defaultConfineConfig(),`):

```go
		Confine: defaultConfineConfig(),
		Audit:   defaultAuditConfig(),
```

In `Validate`, add the audit checks before `return nil`:

```go
	// Check audit retention and segment bounds.
	if c.Audit.RetentionDays < 0 {
		return fmt.Errorf("audit.retention_days must be >= 0, got %d", c.Audit.RetentionDays)
	}
	if c.Audit.SegmentMax < 1 {
		return fmt.Errorf("audit.segment_max must be >= 1, got %d", c.Audit.SegmentMax)
	}
```

The existing `Migrate` already bumps `c.Version` to `CurrentConfigVersion` whenever `c.Version < CurrentConfigVersion`, and `Load` overlays the on-disk YAML onto `DefaultConfig` so a v2 file with no `audit:` block inherits `defaultAuditConfig()`. No new back-fill code is needed — confirm the existing `Migrate` body reads:

```go
func (c *Config) Migrate(fromVersion int) bool {
	changed := false
	if c.Version < CurrentConfigVersion {
		c.Version = CurrentConfigVersion
		changed = true
	}
	return changed
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/settings/ -run 'TestCurrentConfigVersionIsThree|TestDefaultConfigHasAuditDefaults|TestValidateRejectsBadAudit|TestMigrateV2ToV3' -v`
Expected: PASS (4 tests). Also run `go test ./internal/settings/ -v` to confirm existing settings tests still pass.

- [ ] **Step 5: Commit**

```bash
git add internal/settings/settings.go internal/settings/settings_audit_test.go
git commit -m "feat(settings): add AuditConfig block and bump config schema to v3"
```

---

## Task 9: `sentinel audit` CLI command group

**Files:**
- Create: `cmd/audit.go`
- Test: `cmd/audit_test.go`
- Modify: `cmd/root.go` (register the command)

- [ ] **Step 1: Write the failing test**

Create `cmd/audit_test.go`:

```go
package cmd

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inovacc/sentinel/internal/audit"
)

func seedAuditDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	l, err := audit.Open(audit.Options{DBPath: path, SegmentMax: 100})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx := audit.WithActor(context.Background(), "DEV1", "admin")
	for _, et := range []string{audit.EventCertSign, audit.EventExecRun, audit.EventRBACDeny} {
		if err := l.Record(ctx, audit.Event{Type: et, Outcome: audit.OutcomeAllow, Target: "t"}); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	_ = l.Close()
	return path
}

func TestAuditTailCmd(t *testing.T) {
	path := seedAuditDB(t)
	var out bytes.Buffer
	if err := runAuditTail(&out, path, auditFilterFlags{n: 2}); err != nil {
		t.Fatalf("tail: %v", err)
	}
	if !strings.Contains(out.String(), "exec.run") {
		t.Fatalf("tail output missing exec.run: %q", out.String())
	}
}

func TestAuditVerifyCmdClean(t *testing.T) {
	path := seedAuditDB(t)
	var out bytes.Buffer
	if err := runAuditVerify(&out, path, 0); err != nil {
		t.Fatalf("verify clean should succeed: %v", err)
	}
}

func TestAuditVerifyCmdDetectsTamper(t *testing.T) {
	path := seedAuditDB(t)
	// Reopen and tamper.
	l, err := audit.Open(audit.Options{DBPath: path})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if err := l.TamperForTest(); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	_ = l.Close()

	var out bytes.Buffer
	if err := runAuditVerify(&out, path, 0); err == nil {
		t.Fatal("verify should fail on a tampered chain")
	}
}

func TestAuditExportCmdJSON(t *testing.T) {
	path := seedAuditDB(t)
	var out bytes.Buffer
	if err := runAuditExport(&out, path, "json", auditFilterFlags{}); err != nil {
		t.Fatalf("export: %v", err)
	}
	if !strings.Contains(out.String(), "cert.sign") {
		t.Fatalf("export missing cert.sign: %q", out.String())
	}
}
```

Also add a small test-only tamper helper to the audit package. Create `internal/audit/testhelp.go`:

```go
package audit

// TamperForTest corrupts a stored record so Verify will fail. It exists only to
// let CLI-level tests exercise the failure path without reaching into SQL; it is
// not part of the public contract and must not be called in production.
func (l *SQLiteLogger) TamperForTest() error {
	_, err := l.db.Exec(`UPDATE audit_log SET detail = '{"tampered":true}' WHERE seq = 1`)
	return err
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/ -run TestAudit -v`
Expected: FAIL — `undefined: runAuditTail`, `undefined: auditFilterFlags`, `undefined: runAuditVerify`, `undefined: runAuditExport`, `undefined: (*audit.SQLiteLogger).TamperForTest`.

- [ ] **Step 3: Add the tamper helper, then the command**

Create `internal/audit/testhelp.go` as shown in Step 1.

Create `cmd/audit.go`:

```go
package cmd

import (
	"fmt"
	"io"

	"github.com/inovacc/sentinel/internal/audit"
	"github.com/inovacc/sentinel/internal/datadir"
	"github.com/inovacc/sentinel/internal/settings"
	"github.com/spf13/cobra"
)

// auditFilterFlags carries the shared filter flags for tail/query/export.
type auditFilterFlags struct {
	since     string
	until     string
	eventType string
	actor     string
	outcome   string
	n         int
	jsonOut   bool
}

func (f auditFilterFlags) toFilter() audit.Filter {
	return audit.Filter{
		Since:     f.since,
		Until:     f.until,
		EventType: f.eventType,
		Actor:     f.actor,
		Outcome:   audit.Outcome(f.outcome),
		Limit:     f.n,
	}
}

// auditDBPath returns the configured audit db path, falling back to the datadir
// default when the config is unset or unreadable.
func auditDBPath() string {
	cfg, err := settings.Load(datadir.ConfigPath())
	if err == nil && cfg.Audit.DBPath != "" {
		return cfg.Audit.DBPath
	}
	return datadir.AuditDBPath()
}

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Inspect and verify the security audit log",
		Long: `Read-only access to the tamper-evident security audit log at
~/.sentinel/audit.db. Use 'verify' to check chain integrity (exit non-zero on any
break), 'tail'/'query' to inspect events, and 'export' to produce an offline
artifact.`,
		SilenceUsage: true,
	}
	cmd.AddCommand(newAuditTailCmd(), newAuditQueryCmd(), newAuditVerifyCmd(), newAuditExportCmd())
	return cmd
}

func newAuditTailCmd() *cobra.Command {
	var f auditFilterFlags
	cmd := &cobra.Command{
		Use:   "tail",
		Short: "Show the most recent audit events",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAuditTail(cmd.OutOrStdout(), auditDBPath(), f)
		},
	}
	cmd.Flags().StringVar(&f.eventType, "type", "", "filter by event type")
	cmd.Flags().StringVar(&f.actor, "actor", "", "filter by actor device id")
	cmd.Flags().IntVar(&f.n, "n", 50, "number of events to show")
	cmd.Flags().BoolVar(&f.jsonOut, "json", false, "output as JSON")
	return cmd
}

func newAuditQueryCmd() *cobra.Command {
	var f auditFilterFlags
	cmd := &cobra.Command{
		Use:   "query",
		Short: "Query audit events in a time range",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAuditQuery(cmd.OutOrStdout(), auditDBPath(), f)
		},
	}
	cmd.Flags().StringVar(&f.since, "since", "", "RFC3339 lower bound (inclusive)")
	cmd.Flags().StringVar(&f.until, "until", "", "RFC3339 upper bound (inclusive)")
	cmd.Flags().StringVar(&f.eventType, "type", "", "filter by event type")
	cmd.Flags().StringVar(&f.outcome, "outcome", "", "filter by outcome (allow|deny|error)")
	cmd.Flags().BoolVar(&f.jsonOut, "json", false, "output as JSON")
	return cmd
}

func newAuditVerifyCmd() *cobra.Command {
	var fromSegment int
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify audit-log chain integrity (exit non-zero on first break)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAuditVerify(cmd.OutOrStdout(), auditDBPath(), fromSegment)
		},
	}
	cmd.Flags().IntVar(&fromSegment, "from-segment", 0, "start verification at this sealed segment (0 = genesis)")
	return cmd
}

func newAuditExportCmd() *cobra.Command {
	var format string
	var f auditFilterFlags
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export audit events as JSON or CSV to stdout",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAuditExport(cmd.OutOrStdout(), auditDBPath(), format, f)
		},
	}
	cmd.Flags().StringVar(&format, "format", "json", "output format (json|csv)")
	cmd.Flags().StringVar(&f.since, "since", "", "RFC3339 lower bound (inclusive)")
	cmd.Flags().StringVar(&f.eventType, "type", "", "filter by event type")
	return cmd
}

func openAuditReader(path string) (*audit.SQLiteLogger, error) {
	l, err := audit.Open(audit.Options{DBPath: path})
	if err != nil {
		return nil, fmt.Errorf("open audit db: %w", err)
	}
	return l, nil
}

func runAuditTail(w io.Writer, path string, f auditFilterFlags) error {
	l, err := openAuditReader(path)
	if err != nil {
		return err
	}
	defer func() { _ = l.Close() }()

	rows, err := l.Tail(f.toFilter())
	if err != nil {
		return err
	}
	return writeAuditRows(w, rows, f.jsonOut)
}

func runAuditQuery(w io.Writer, path string, f auditFilterFlags) error {
	l, err := openAuditReader(path)
	if err != nil {
		return err
	}
	defer func() { _ = l.Close() }()

	rows, err := l.Query(f.toFilter())
	if err != nil {
		return err
	}
	return writeAuditRows(w, rows, f.jsonOut)
}

func runAuditVerify(w io.Writer, path string, fromSegment int) error {
	l, err := openAuditReader(path)
	if err != nil {
		return err
	}
	defer func() { _ = l.Close() }()

	brk, err := l.Verify(fromSegment)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	if brk != nil {
		_, _ = fmt.Fprintf(w, "INTEGRITY FAILURE: %s\n", brk.Error())
		return fmt.Errorf("audit chain broken at seq %d (%s)", brk.Seq, brk.Kind)
	}
	_, _ = fmt.Fprintln(w, "audit chain OK")
	return nil
}

func runAuditExport(w io.Writer, path, format string, f auditFilterFlags) error {
	l, err := openAuditReader(path)
	if err != nil {
		return err
	}
	defer func() { _ = l.Close() }()

	return l.Export(w, format, f.toFilter())
}

func writeAuditRows(w io.Writer, rows []audit.Row, jsonOut bool) error {
	if jsonOut {
		// Reuse the JSON exporter shape for a single consistent format.
		enc := newJSONEncoder(w)
		return enc.Encode(rows)
	}
	for _, r := range rows {
		_, _ = fmt.Fprintf(w, "%d\t%s\t%s\t%s/%s\t%s\t%s\n",
			r.Seq, r.TS, r.EventType, r.ActorDeviceID, r.ActorRole, r.Outcome, r.Target)
	}
	return nil
}
```

Add the small JSON encoder helper at the bottom of `cmd/audit.go` (keeps the import list local and avoids pulling `encoding/json` into other cmd files):

```go
func newJSONEncoder(w io.Writer) *jsonEncoder { return &jsonEncoder{w: w} }

type jsonEncoder struct{ w io.Writer }

func (e *jsonEncoder) Encode(v any) error {
	enc := jsonNewEncoder(e.w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("encode json: %w", err)
	}
	return nil
}
```

And add the `encoding/json` alias import at the top of `cmd/audit.go`:

```go
import (
	"fmt"
	"io"

	jsonpkg "encoding/json"

	"github.com/inovacc/sentinel/internal/audit"
	"github.com/inovacc/sentinel/internal/datadir"
	"github.com/inovacc/sentinel/internal/settings"
	"github.com/spf13/cobra"
)

// jsonNewEncoder is a thin alias so the encoder helper reads cleanly.
func jsonNewEncoder(w io.Writer) *jsonpkg.Encoder { return jsonpkg.NewEncoder(w) }
```

Add the datadir helper. In `internal/datadir/datadir.go`, add next to the existing `DBPath()`:

```go
// AuditDBPath returns the default path to the security audit database.
func AuditDBPath() string { return filepath.Join(Root(), "audit.db") }
```

Register the command in `cmd/root.go` where the other subcommands are added (alongside `newDoctorCmd()`):

```go
	rootCmd.AddCommand(newAuditCmd())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/ -run TestAudit -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add cmd/audit.go cmd/audit_test.go cmd/root.go internal/audit/testhelp.go internal/datadir/datadir.go
git commit -m "feat(cmd): add 'sentinel audit tail|query|verify|export' command group"
```

---

## Task 10: Daemon wiring + tiered fail-closed emission at each point

**Files:**
- Modify: `cmd/serve.go`
- Modify: `internal/grpc/server.go`
- Modify: `internal/grpc/interceptor.go`
- Modify: `internal/exec/exec.go`
- Modify: `internal/worker/pool.go`
- Test: `internal/grpc/interceptor_audit_test.go`
- Test: `cmd/serve_audit_test.go`

- [ ] **Step 1: Write the failing test (interceptor emits + fails closed on deny)**

Create `internal/grpc/interceptor_audit_test.go`:

```go
package grpc

import (
	"context"
	"errors"
	"testing"

	"github.com/inovacc/sentinel/internal/audit"
)

// recordingLogger captures emitted events and can be made to fail.
type recordingLogger struct {
	events []audit.Event
	failOn map[string]bool // event types that should return an error
}

func (r *recordingLogger) Record(_ context.Context, ev audit.Event) error {
	r.events = append(r.events, ev)
	if r.failOn[ev.Type] {
		return errors.New("simulated audit write failure")
	}
	return nil
}
func (r *recordingLogger) Close() error { return nil }

func TestAuditEventForMethodTier(t *testing.T) {
	tests := []struct {
		method  string
		role    string
		allowed bool
		want    string
	}{
		{"/sentinel.v1.FleetService/AcceptPairing", "admin", true, audit.EventRBACAllowPrivileged},
		{"/sentinel.v1.FileSystemService/ReadFile", "reader", true, audit.EventRBACAllowRead},
		{"/sentinel.v1.ExecService/Exec", "reader", false, audit.EventRBACDeny},
	}
	for _, tt := range tests {
		got := auditEventForMethod(tt.method, tt.allowed)
		if got != tt.want {
			t.Errorf("method %s allowed=%v: event = %s, want %s", tt.method, tt.allowed, got, tt.want)
		}
	}
}

func TestCriticalAuditFailureBlocksAllow(t *testing.T) {
	rec := &recordingLogger{failOn: map[string]bool{audit.EventRBACAllowPrivileged: true}}
	// emitAccessAudit must return an error when a critical event fails to write,
	// so the interceptor aborts the privileged call (fail-closed).
	err := emitAccessAudit(context.Background(), rec,
		"/sentinel.v1.FleetService/AcceptPairing", "admin", true)
	if err == nil {
		t.Fatal("critical audit write failure must block the operation")
	}
}

func TestRoutineAuditFailureDoesNotBlock(t *testing.T) {
	rec := &recordingLogger{failOn: map[string]bool{audit.EventRBACAllowRead: true}}
	err := emitAccessAudit(context.Background(), rec,
		"/sentinel.v1.FileSystemService/ReadFile", "reader", true)
	if err != nil {
		t.Fatalf("routine audit write failure must not block: %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/grpc/ -run 'TestAuditEventForMethod|TestCriticalAuditFailure|TestRoutineAuditFailure' -v`
Expected: FAIL — `undefined: auditEventForMethod`, `undefined: emitAccessAudit`.

- [ ] **Step 3: Add the interceptor emission logic**

Add to `internal/grpc/interceptor.go` (extend the imports to include `audit`, `ca`, `crypto/sha256`, `encoding/hex`, `strings`):

```go
import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/inovacc/sentinel/internal/audit"
	"github.com/inovacc/sentinel/internal/ca"
	"github.com/inovacc/sentinel/internal/rbac"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)
```

Add the classification helper and emission function:

```go
// privilegedMethods are mutating/admin RPCs whose successful authorization is a
// CRITICAL audit event. Everything else that is allowed is a routine read.
var privilegedMethods = map[string]bool{
	"/sentinel.v1.FleetService/Register":        true,
	"/sentinel.v1.FleetService/AcceptPairing":   true,
	"/sentinel.v1.SessionService/Destroy":       true,
	"/sentinel.v1.ExecService/Exec":             true,
	"/sentinel.v1.ExecService/ExecStream":       true,
	"/sentinel.v1.FileSystemService/WriteFile":  true,
	"/sentinel.v1.FileSystemService/Upload":     true,
	"/sentinel.v1.FileSystemService/Delete":     true,
	"/sentinel.v1.SessionService/Create":        true,
	"/sentinel.v1.SessionService/Resume":        true,
	"/sentinel.v1.SessionService/Pause":         true,
	"/sentinel.v1.SessionService/Checkpoint":    true,
	"/sentinel.v1.PayloadService/Send":          true,
	"/sentinel.v1.PayloadService/SendStream":    true,
	"/sentinel.v1.WorkerService/Spawn":          true,
	"/sentinel.v1.WorkerService/Kill":           true,
	"/sentinel.v1.WorkerService/KillAll":        true,
}

// auditEventForMethod returns the audit event type for an RBAC decision.
func auditEventForMethod(method string, allowed bool) string {
	if !allowed {
		return audit.EventRBACDeny
	}
	if privilegedMethods[method] {
		return audit.EventRBACAllowPrivileged
	}
	return audit.EventRBACAllowRead
}

// emitAccessAudit records the RBAC decision and applies the tiered fail-closed
// posture: a write failure on a CRITICAL event (deny or privileged allow) is
// returned so the caller aborts the operation; a routine read failure is
// swallowed (the logger already mirrors it to slog and bumps its metric).
func emitAccessAudit(ctx context.Context, logger audit.Logger, method, role string, allowed bool) error {
	if logger == nil {
		return nil
	}
	evType := auditEventForMethod(method, allowed)
	outcome := audit.OutcomeAllow
	if !allowed {
		outcome = audit.OutcomeDeny
	}
	ev := audit.Event{
		Type:    evType,
		Outcome: outcome,
		Target:  method,
		Detail:  map[string]any{"method": method, "role": role},
	}
	err := logger.Record(ctx, ev)
	if err == nil {
		return nil
	}
	// Routine reads fail open; critical events fail closed. The tier comes from
	// the single exported catalog in internal/audit — no mirrored map here, so a
	// newly-classified event cannot drift out of sync (spec §10 biggest risk).
	if crit, _ := audit.CriticalityOf(evType); crit == audit.Routine {
		return nil
	}
	return fmt.Errorf("audit: refusing to proceed unaudited: %w", err)
}

// deviceIDFromCert derives a stable actor id from the peer certificate: the
// SHA-256 of its raw DER, hex-encoded. This is the anti-forgery actor — it comes
// from the verified mTLS chain, never from the request body.
func deviceIDFromCert(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
```

Modify `checkAccess` to seed the actor, return the decision, and emit. Replace the existing `checkAccess` with:

```go
// checkAccess extracts the peer certificate, verifies the role against policy,
// seeds the audit actor, and emits the RBAC decision. The returned context
// carries the actor so downstream handlers' audit records are attributed.
func checkAccess(ctx context.Context, method string, policy *rbac.Policy, logger audit.Logger) (context.Context, error) {
	cert, err := extractPeerCert(ctx)
	if err != nil {
		return ctx, status.Errorf(codes.Unauthenticated, "mtls: %v", err)
	}
	role, err := ca.ExtractRole(cert)
	if err != nil {
		return ctx, status.Errorf(codes.Unauthenticated, "mtls: failed to extract role: %v", err)
	}

	actorCtx := audit.WithActor(ctx, deviceIDFromCert(cert), role)

	if perr := policy.Check(method, role); perr != nil {
		// Denied: emit a critical rbac.deny. If even the audit write fails we
		// still deny (the policy error stands); we just surface the audit failure
		// in the message for the operator.
		if aerr := emitAccessAudit(actorCtx, logger, method, role, false); aerr != nil {
			return actorCtx, status.Errorf(codes.PermissionDenied, "%v (audit: %v)", perr, aerr)
		}
		return actorCtx, status.Errorf(codes.PermissionDenied, "%v", perr)
	}

	// Allowed: emit allow event. A critical allow whose audit write fails must
	// abort the call (fail-closed) so nothing privileged happens un-audited.
	if aerr := emitAccessAudit(actorCtx, logger, method, role, true); aerr != nil {
		return actorCtx, status.Errorf(codes.Unavailable, "audit unavailable: %v", aerr)
	}
	return actorCtx, nil
}
```

Update the two interceptor closures to thread the logger and the returned context:

```go
func unaryRBACInterceptor(policy *rbac.Policy, logger audit.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		actorCtx, err := checkAccess(ctx, info.FullMethod, policy, logger)
		if err != nil {
			return nil, err
		}
		return handler(actorCtx, req)
	}
}

func streamRBACInterceptor(policy *rbac.Policy, logger audit.Logger) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		actorCtx, err := checkAccess(ss.Context(), info.FullMethod, policy, logger)
		if err != nil {
			return err
		}
		return handler(srv, &auditServerStream{ServerStream: ss, ctx: actorCtx})
	}
}

// auditServerStream overrides Context so the seeded actor reaches the handler.
type auditServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *auditServerStream) Context() context.Context { return s.ctx }
```

- [ ] **Step 4: Run interceptor test to verify it passes**

Run: `go test ./internal/grpc/ -run 'TestAuditEventForMethod|TestCriticalAuditFailure|TestRoutineAuditFailure' -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Thread the logger through the gRPC server constructor**

In `internal/grpc/server.go`, find where `unaryRBACInterceptor(policy)` and `streamRBACInterceptor(policy)` are called and pass the logger. Add an `audit.Logger` field to the server struct and accept it in the constructor. The exact constructor is `NewServer(...)`; add a parameter `auditLogger audit.Logger` and store it, defaulting to `audit.NopLogger{}` when nil:

```go
	if auditLogger == nil {
		auditLogger = audit.NopLogger{}
	}
	// ... where interceptors are built:
	grpc.UnaryInterceptor(unaryRBACInterceptor(policy, auditLogger)),
	grpc.StreamInterceptor(streamRBACInterceptor(policy, auditLogger)),
```

Add the import `"github.com/inovacc/sentinel/internal/audit"` to `server.go`. Existing callers in tests that call `NewServer` without the logger should pass `audit.NopLogger{}` (or `nil`, which is defaulted). Update those call sites to compile.

- [ ] **Step 6: Add exec emission (`exec.run` routine, `confine.refuse` critical)**

In `internal/exec/exec.go`, add an audit logger to `Runner` and emit. Extend imports with `"github.com/inovacc/sentinel/internal/audit"`. Add the field and a setter mirroring the confiner injection:

```go
type Runner struct {
	sandbox  *sandbox.Sandbox
	confiner confine.Confiner
	auditLog audit.Logger
	logger   *slog.Logger
	warnOnce sync.Once
}
```

Update `NewRunnerWithConfiner` to accept and store the logger (default to `NopLogger`):

```go
// NewRunnerWithConfiner injects a confiner, audit logger, and slog logger.
func NewRunnerWithConfiner(sb *sandbox.Sandbox, c confine.Confiner, al audit.Logger, logger *slog.Logger) *Runner {
	if logger == nil {
		logger = slog.Default()
	}
	if al == nil {
		al = audit.NopLogger{}
	}
	return &Runner{sandbox: sb, confiner: c, auditLog: al, logger: logger}
}
```

And ensure `NewRunner` sets a non-nil audit logger:

```go
func NewRunner(sb *sandbox.Sandbox) *Runner {
	return &Runner{sandbox: sb, auditLog: audit.NopLogger{}}
}
```

In `applyConfine`, when `refuse` is true, emit a critical `confine.refuse` and return an error if the audit write fails (fail-closed, alongside the existing refusal):

```go
	if refuse {
		_ = p.Kill()
		_, _ = p.Wait()
		if r.auditLog != nil {
			if aerr := r.auditLog.Record(context.Background(), audit.Event{
				Type:    audit.EventConfineRefuse,
				Outcome: audit.OutcomeDeny,
				Target:  "exec",
				Detail:  map[string]any{"reason": "unconfined process refused"},
			}); aerr != nil {
				return fmt.Errorf("exec: refusing unconfined process (audit failed: %v): %w", aerr, err)
			}
		}
		return fmt.Errorf("exec: refusing unconfined process: %w", err)
	}
```

In `Run`, after a successful `cmd.Start()` + confinement, emit a routine `exec.run` (log-and-continue; do not abort on audit failure). Insert just before `runErr := cmd.Wait()`:

```go
	_ = r.auditLog.Record(ctx, audit.Event{
		Type:    audit.EventExecRun,
		Outcome: audit.OutcomeAllow,
		Target:  req.Command,
		Detail:  map[string]any{"command": req.Command, "argv": req.Args, "cwd": cmd.Dir},
	})
```

- [ ] **Step 7: Add worker emission (`confine.refuse` critical)**

In `internal/worker/pool.go`, add an audit logger option and field (mirroring `WithConfiner`). Extend imports with `"github.com/inovacc/sentinel/internal/audit"`:

```go
// WithAuditLogger sets the security audit logger.
func WithAuditLogger(l audit.Logger) Option { return func(p *Pool) { p.auditLog = l } }
```

Add `auditLog audit.Logger` to the `Pool` struct, and default it in `NewPool` (after the options loop):

```go
	if p.auditLog == nil {
		p.auditLog = audit.NopLogger{}
	}
```

At the unconfined-refusal abort in `Spawn` (where it currently returns `worker: refusing unconfined process`), emit the critical event and fail closed:

```go
		_, _ = cmd.Process.Wait()
		if aerr := p.auditLog.Record(ctx, audit.Event{
			Type:    audit.EventConfineRefuse,
			Outcome: audit.OutcomeDeny,
			Target:  command,
			Detail:  map[string]any{"command": command, "reason": "unconfined worker refused"},
		}); aerr != nil {
			return nil, fmt.Errorf("worker: refusing unconfined process (audit failed: %v): %w", aerr, cErr)
		}
		return nil, fmt.Errorf("worker: refusing unconfined process: %w", cErr)
```

- [ ] **Step 8: Write the daemon-wiring test**

Create `cmd/serve_audit_test.go`:

```go
package cmd

import (
	"path/filepath"
	"testing"

	"github.com/inovacc/sentinel/internal/audit"
	"github.com/inovacc/sentinel/internal/settings"
)

func TestBuildAuditLoggerEnabled(t *testing.T) {
	cfg := settings.DefaultConfig()
	cfg.Audit.DBPath = filepath.Join(t.TempDir(), "audit.db")
	l, err := buildAuditLogger(cfg, nil)
	if err != nil {
		t.Fatalf("buildAuditLogger: %v", err)
	}
	defer func() { _ = l.Close() }()
	if _, ok := l.(*audit.SQLiteLogger); !ok {
		t.Fatalf("enabled config should yield a SQLiteLogger, got %T", l)
	}
}

func TestBuildAuditLoggerDisabledIsNop(t *testing.T) {
	cfg := settings.DefaultConfig()
	cfg.Audit.Enabled = false
	l, err := buildAuditLogger(cfg, nil)
	if err != nil {
		t.Fatalf("buildAuditLogger: %v", err)
	}
	defer func() { _ = l.Close() }()
	if _, ok := l.(audit.NopLogger); !ok {
		t.Fatalf("disabled config should yield NopLogger, got %T", l)
	}
}
```

- [ ] **Step 9: Add daemon wiring in `cmd/serve.go`**

Add the audit import `"github.com/inovacc/sentinel/internal/audit"`. Add the builder:

```go
// buildAuditLogger constructs the security audit logger from config. A disabled
// audit config yields a NopLogger so the rest of the wiring is unconditional.
func buildAuditLogger(cfg *settings.Config, logger *slog.Logger) (audit.Logger, error) {
	if !cfg.Audit.Enabled {
		return audit.NopLogger{}, nil
	}
	dbPath := cfg.Audit.DBPath
	if dbPath == "" {
		dbPath = datadir.AuditDBPath()
	}
	l, err := audit.Open(audit.Options{
		DBPath:        dbPath,
		SegmentMax:    cfg.Audit.SegmentMax,
		RetentionDays: cfg.Audit.RetentionDays,
		Logger:        logger,
	})
	if err != nil {
		return nil, fmt.Errorf("init audit logger: %w", err)
	}
	return l, nil
}
```

Add an `auditLog audit.Logger` field to the `daemon` struct. In `buildDaemon`, after the confiner is built and `addCleanup`'d, build and register the audit logger and emit `daemon.start`:

```go
	auditLog, err := buildAuditLogger(cfg, logger)
	if err != nil {
		return d, err
	}
	d.auditLog = auditLog
	d.addCleanup(func() { _ = auditLog.Close() })
	_ = auditLog.Record(context.Background(), audit.Event{
		Type:    audit.EventDaemonStart,
		Outcome: audit.OutcomeAllow,
		Target:  d.deviceID,
		Detail:  map[string]any{"device_id": d.deviceID},
	})
	d.addCleanup(func() {
		_ = auditLog.Record(context.Background(), audit.Event{
			Type:    audit.EventDaemonStop,
			Outcome: audit.OutcomeAllow,
			Target:  d.deviceID,
		})
	})
```

NOTE: register the `daemon.stop` cleanup BEFORE the `auditLog.Close()` cleanup so the stop event is written before the db closes. Since cleanups run LIFO, add the `Close` cleanup first, then the `daemon.stop` cleanup, then continue. Reorder the two `addCleanup` calls accordingly:

```go
	d.addCleanup(func() { _ = auditLog.Close() })          // runs last (LIFO)
	d.addCleanup(func() {                                   // runs before Close
		_ = auditLog.Record(context.Background(), audit.Event{
			Type: audit.EventDaemonStop, Outcome: audit.OutcomeAllow, Target: d.deviceID})
	})
```

Pass `auditLog` into the worker pool and runner wiring. Update the `worker.NewPool` call:

```go
	d.workerPool, err = worker.NewPool(db, sb, worker.WithLogger(logger), worker.WithConfiner(confiner), worker.WithAuditLogger(auditLog))
```

Update `registerServices` to accept and forward `auditLog` to `NewRunnerWithConfiner` and `NewServer`. Find the `runner := exec.NewRunnerWithConfiner(...)` call inside `registerServices` and pass `auditLog`; pass `auditLog` to `sentinelgrpc.NewServer(...)`. Thread `auditLog audit.Logger` through the `registerServices` signature and the `NewServer` call site in `buildDaemon`/`serve`.

- [ ] **Step 10: Add fleet and transport/cert emission points**

In `internal/fleet/registry.go`, add audit emission to `SetCAPin`, `AddPending`, and `Remove`. Rather than coupling `fleet` to `audit` directly (keeping it dependency-light), emit from the callers. The callers are: the transport pairing path (`pkg/transport` bootstrap `OnPeerAccepted`) and `cmd/connect.go`. In `cmd/serve.go`, the `OnPeerAccepted` callback (`buildTransport`) already runs `registry.AddPending` + `registry.SetCAPin` on a successful pairing — wrap those with audit emission. After a successful accept, emit critical `pairing.accept`, `fleet.add`, `capin.change`, and `cert.sign`:

```go
	// inside the OnPeerAccepted callback in buildTransport, after AddPending/SetCAPin succeed:
	for _, ev := range []audit.Event{
		{Type: audit.EventPairingAccept, Outcome: audit.OutcomeAllow, Target: peerDeviceID, Detail: map[string]any{"device_id": peerDeviceID}},
		{Type: audit.EventFleetAdd, Outcome: audit.OutcomeAllow, Target: peerDeviceID},
		{Type: audit.EventCAPinChange, Outcome: audit.OutcomeAllow, Target: peerDeviceID, Detail: map[string]any{"fingerprint": caFingerprint}},
		{Type: audit.EventCertSign, Outcome: audit.OutcomeAllow, Target: peerDeviceID, Detail: map[string]any{"role": signedRole}},
	} {
		if aerr := auditLog.Record(context.Background(), ev); aerr != nil {
			// Critical: refuse the pairing rather than complete it un-audited.
			return fmt.Errorf("pairing: refusing to complete unaudited: %w", aerr)
		}
	}
```

For a rejected/conflicting pairing in the same callback, emit `pairing.reject` / `pairing.conflict` (critical) with outcome `deny`. Thread `auditLog` into `buildTransport`'s signature so the callback closes over it. The exact local variable names (`peerDeviceID`, `caFingerprint`, `signedRole`) must match those already in scope in `buildTransport`'s `OnPeerAccepted`; if they differ, use the in-scope names (the device id, the CA fingerprint string, and the role granted at signing).

In `cmd/renew.go`, emit `daemon.renew` at the start of `runRenew` and `cert.renew` (critical) for each re-paired peer in its `OnPeerAccepted`. Build a logger via `buildAuditLogger(cfg, logger)` (reuse the helper) and `defer Close`. At the top of `runRenew` after `cfg` is loaded:

```go
	auditLog, aerr := buildAuditLogger(cfg, logger)
	if aerr != nil {
		return aerr
	}
	defer func() { _ = auditLog.Close() }()
	_ = auditLog.Record(context.Background(), audit.Event{
		Type: audit.EventDaemonRenew, Outcome: audit.OutcomeAllow, Target: "self"})
```

and in the renew `OnPeerAccepted`, emit critical `cert.renew` for the re-signed peer, failing closed on audit error exactly as in the serve path.

For `sandbox.deny`: emit at the gRPC service boundary where `CheckExec`/`CheckRead`/`ResolvePath` errors are surfaced, since `internal/sandbox` stays dependency-free. In `internal/grpc/exec_service.go` and `internal/grpc/fs_service.go`, where a sandbox error is returned to the client, emit a critical `sandbox.deny` (outcome `deny`) using the per-service `audit.Logger` (add an `audit.Logger` field to those service structs, defaulted to `NopLogger`, set from `registerServices`). Example wrapper used at each sandbox-error return:

```go
func emitSandboxDeny(ctx context.Context, al audit.Logger, target, reason string) error {
	if al == nil {
		return nil
	}
	if err := al.Record(ctx, audit.Event{
		Type:    audit.EventSandboxDeny,
		Outcome: audit.OutcomeDeny,
		Target:  target,
		Detail:  map[string]any{"reason": reason, "path": target},
	}); err != nil {
		return fmt.Errorf("audit: sandbox deny unrecorded: %w", err)
	}
	return nil
}
```

For `fs.read` (routine): in `internal/grpc/fs_service.go` `ReadFile` success path, emit `fs.read` (outcome allow, log-and-continue).

- [ ] **Step 11: Run the daemon-wiring tests**

Run: `go test ./cmd/ -run 'TestBuildAuditLogger' -v`
Expected: PASS (2 tests).

- [ ] **Step 12: Build the whole module and run the full suite**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: all packages compile and pass. Fix any call sites of `NewServer`, `NewRunnerWithConfiner`, `NewPool`, `unaryRBACInterceptor`, `checkAccess`, and `buildTransport`/`registerServices` whose signatures changed so existing tests pass an `audit.NopLogger{}` (or `nil`).

- [ ] **Step 13: Commit**

```bash
git add cmd/serve.go cmd/renew.go internal/grpc/server.go internal/grpc/interceptor.go internal/grpc/interceptor_audit_test.go internal/grpc/exec_service.go internal/grpc/fs_service.go internal/exec/exec.go internal/worker/pool.go cmd/serve_audit_test.go
git commit -m "feat(audit): wire tiered fail-closed emission into rbac, exec, worker, fleet, pairing, sandbox"
```

---

## Task 11: Cross-build, registry guard for no-op default, and documentation

**Files:**
- Test: `internal/audit/nop_test.go`
- Modify: `docs/security/THREAT-MODEL.md`
- Modify: `docs/superpowers/HARDENING-STATUS.md`

- [ ] **Step 1: Write the no-op regression-guard test**

Create `internal/audit/nop_test.go`:

```go
package audit

import (
	"context"
	"testing"
)

// TestNopLoggerSatisfiesInterface guards that NopLogger remains a usable Logger
// (the zero value relied on by existing callers and tests).
func TestNopLoggerSatisfiesInterface(t *testing.T) {
	var l Logger = NopLogger{}
	if err := l.Record(context.Background(), Event{Type: EventExecRun, Outcome: OutcomeAllow}); err != nil {
		t.Fatalf("NopLogger.Record returned error: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("NopLogger.Close returned error: %v", err)
	}
}

// TestSQLiteLoggerSatisfiesInterface guards the real implementation conforms.
func TestSQLiteLoggerSatisfiesInterface(t *testing.T) {
	var _ Logger = (*SQLiteLogger)(nil)
}
```

- [ ] **Step 2: Run test to verify it passes (no impl needed — guard only)**

Run: `go test ./internal/audit/ -run 'TestNopLogger|TestSQLiteLoggerSatisfies' -v`
Expected: PASS (2 tests). If `TestSQLiteLoggerSatisfiesInterface` fails to compile, the `SQLiteLogger` is missing a `Record`/`Close` method — fix it in Task 3's file.

- [ ] **Step 3: Run the linux cross-build**

Run (PowerShell): `$env:GOOS="linux"; go build ./...; $env:GOOS=""`
Expected: compiles cleanly on linux (the `confine_other.go` no-op path + audit are platform-agnostic).

Run the linter:
Run: `golangci-lint run --fix ./... --timeout=5m`
Expected: no findings.

- [ ] **Step 4: Update the threat model**

In `docs/security/THREAT-MODEL.md`, locate the rows for T2.5, T7.3 (repudiation) and T8.3 (audit-trail integrity). Set their **Status** to ✅ and their **Mitigation/Code/Test** columns to cite the audit log. For each of the three rows, edit the trailing columns to read (adapt the surrounding table cells to the existing column layout):

```
| ... | Tamper-evident, actor-attributed, hash-chained security audit log; critical events fail-closed; `sentinel audit verify` detects edit/reorder/truncation | `internal/audit/*`, `cmd/audit.go`, RBAC interceptor emission | `internal/audit/*_test.go`, `internal/grpc/interceptor_audit_test.go` | ✅ — Phase 3.1 (2026-06-04) |
```

If T2.5/T7.3/T8.3 do not yet exist as rows, add them under the appropriate trust-boundary section (TB7 SQLite/on-disk state for T8.3; TB2 mTLS for the repudiation rows) using the existing `| ID | STRIDE | Threat | Sev | Mitigation | Code | Test | Status |` column format.

- [ ] **Step 5: Add the hardening-campaign entry**

At the top of `docs/superpowers/HARDENING-STATUS.md` (above the existing OS-sandbox / CA-trust campaign sections and matching their format), add a Phase 3.1 section:

```markdown
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
```

- [ ] **Step 6: Commit**

```bash
git add internal/audit/nop_test.go docs/security/THREAT-MODEL.md docs/superpowers/HARDENING-STATUS.md
git commit -m "docs(security): close T2.5/T7.3/T8.3 with the audit log; add Phase 3.1 campaign entry"
```

---

## Self-Review (completed by plan author)

**Spec coverage (§11 Deliverables Checklist → task):**
- `internal/audit` Logger/Event/NopLogger/store/hash-chain/verify → Tasks 1–4, 7.
- `WithActor` + extraction at RBAC/transport boundary → Task 1 (`WithActor`/`actorFromContext`), Task 10 (`checkAccess` seeds it from the peer cert).
- Event catalog with static criticality + registry-completeness test → Task 1.
- Tiered fail-closed/-open wiring at each emission point → Task 10.
- Sealed-segment retention + prune → Task 6.
- `sentinel audit tail|query|verify|export` CLI → Task 9.
- `AuditConfig` settings block + v2→v3 migration → Task 8.
- `cmd/serve.go` wiring + `Close()` via `addCleanup` → Task 10 (Steps 9, with LIFO ordering note).
- Threat-model update + HARDENING campaign entry → Task 11 (campaign log is `docs/superpowers/HARDENING-STATUS.md`, alongside the OS-sandbox and CA-trust entries).
- Full TDD suite + build/vet/test/lint + linux cross-build → every task + Task 11 Steps 3, 12.

**Placeholder scan:** No "TODO"/"TBD"/"similar to Task N" remain. Two explicit stubs (`redactDetail`, `sealSegment`) are introduced in Task 3 and *removed* in Tasks 5 and 6 respectively, each with the exact deletion called out — this is an intentional, tracked sequencing, not a placeholder.

**Type consistency:** `Event{Type,Outcome,Target,Detail}` is identical across Tasks 1, 3, 7, 9, 10. `record` fields and order match between `hashchain.go` (Task 2), `store.go` (Task 3), and `verify.go` (Task 4). `Append` is internal `append`; the public entry is `Record` everywhere. `CriticalityOf`/`Tier` naming: the catalog exposes the **exported** `CriticalityOf` (Task 1); the gRPC package calls `audit.CriticalityOf` directly — single source of truth, no mirrored map (spec §10 anti-drift). `Filter`/`Row`/`Options`/`SQLiteLogger`/`VerifyBreak`/`BreakKind` are consistent across Tasks 3, 4, 6, 7, 9.

**Resolved ambiguities:**
1. The campaign entry goes in `docs/superpowers/HARDENING-STATUS.md` (the campaign-status log that already holds the OS-sandbox and CA-trust entries); `docs/security/EVIDENCE-HARDENING-FINDINGS.md` stays the findings inventory and is left unchanged.
2. Spec leaves actor-device-id derivation unspecified; resolved by deriving it as `"sha256:"+hex(SHA-256(cert.Raw))` from the verified peer cert (Task 10 `deviceIDFromCert`), which is anti-forgery and matches the repo's Syncthing-style cert-hash identity convention.
3. `sandbox.deny` emission: the spec lists `internal/sandbox` as the source, but the package is intentionally dependency-free; resolved by emitting at the gRPC service boundary (where sandbox errors surface) per the same "emit from caller" rule the spec applies to `internal/ca`.
