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
