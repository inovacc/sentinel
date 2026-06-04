package audit

import "fmt"

// BreakKind classifies a detected chain break.
type BreakKind string

const (
	BreakEdit       BreakKind = "edit"        // recomputed hash != stored hash
	BreakReorder    BreakKind = "reorder"     // prev_hash != prior record's hash
	BreakTruncation BreakKind = "truncation"  // meta last_seq > max(seq) present
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
