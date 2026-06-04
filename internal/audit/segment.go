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

	// anchor_hash is the prev_hash of the segment's first record — i.e. the
	// terminal hash of the prior segment. Verify(N) uses it as the starting
	// prevHash so the retained chain verifies cleanly after old segments are pruned.
	var anchorHash string
	if err := tx.QueryRow(
		`SELECT prev_hash FROM audit_log WHERE seq = ?`, firstSeq,
	).Scan(&anchorHash); err != nil {
		return fmt.Errorf("seal: anchor hash: %w", err)
	}

	if _, err := tx.Exec(
		`INSERT OR REPLACE INTO audit_segments (segment_id, first_seq, last_seq, anchor_hash, sealed_at)
		 VALUES (?, ?, ?, ?, ?)`,
		segment, firstSeq, lastSeq, anchorHash, time.Now().UTC().Format(time.RFC3339Nano),
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
