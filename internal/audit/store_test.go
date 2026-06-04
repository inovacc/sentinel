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
