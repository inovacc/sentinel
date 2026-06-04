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
