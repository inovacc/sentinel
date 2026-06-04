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
