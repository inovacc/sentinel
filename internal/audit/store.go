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
		 VALUES (1, ?, 0, '', 0)`,
		genesis,
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

// statFile is a thin wrapper so permission tests can stat the db path without
// re-importing os in test files that build on only one platform.
func statFile(path string) (os.FileInfo, error) { return os.Stat(path) }

