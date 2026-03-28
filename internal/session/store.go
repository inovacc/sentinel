package session

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// migrateSchema creates the session tables if they don't exist.
func migrateSchema(db *sql.DB) error {
	const schema = `
CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    device_id   TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active',
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    resumed_at  INTEGER,
    context     TEXT,
    error_info  TEXT DEFAULT '',
    metadata    TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_sessions_device ON sessions(device_id);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);

CREATE TABLE IF NOT EXISTS session_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    timestamp   INTEGER NOT NULL,
    event_type  TEXT NOT NULL,
    data        BLOB NOT NULL,
    sequence    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_session ON session_events(session_id);

CREATE TABLE IF NOT EXISTS session_checkpoints (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    timestamp   INTEGER NOT NULL,
    state       TEXT NOT NULL,
    description TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_checkpoints_session ON session_checkpoints(session_id);
`
	_, err := db.Exec(schema)
	if err != nil {
		return fmt.Errorf("migrate schema: %w", err)
	}
	return nil
}

// insertSession inserts a new session row.
func insertSession(db *sql.DB, s *Session) error {
	ctxJSON, err := json.Marshal(s.Context)
	if err != nil {
		return fmt.Errorf("marshal context: %w", err)
	}
	metaJSON, err := json.Marshal(s.Metadata)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	_, err = db.Exec(
		`INSERT INTO sessions (id, device_id, status, created_at, updated_at, context, error_info, metadata)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		s.ID,
		s.DeviceID,
		string(s.Status),
		s.CreatedAt.Unix(),
		s.UpdatedAt.Unix(),
		string(ctxJSON),
		s.ErrorInfo,
		string(metaJSON),
	)
	if err != nil {
		return fmt.Errorf("insert session: %w", err)
	}
	return nil
}

// selectSession retrieves a session by ID.
func selectSession(db *sql.DB, id string) (*Session, error) {
	row := db.QueryRow(
		`SELECT id, device_id, status, created_at, updated_at, resumed_at, context, error_info, metadata
		 FROM sessions WHERE id = ?`, id,
	)
	return scanSession(row)
}

// scanSession scans a single session row.
func scanSession(row *sql.Row) (*Session, error) {
	var (
		s             Session
		createdAt     int64
		updatedAt     int64
		resumedAt     sql.NullInt64
		ctxJSON       sql.NullString
		metaJSON      sql.NullString
		statusStr     string
	)

	err := row.Scan(
		&s.ID, &s.DeviceID, &statusStr,
		&createdAt, &updatedAt, &resumedAt,
		&ctxJSON, &s.ErrorInfo, &metaJSON,
	)
	if err != nil {
		return nil, fmt.Errorf("scan session: %w", err)
	}

	s.Status = Status(statusStr)
	s.CreatedAt = time.Unix(createdAt, 0)
	s.UpdatedAt = time.Unix(updatedAt, 0)

	if resumedAt.Valid {
		t := time.Unix(resumedAt.Int64, 0)
		s.ResumedAt = &t
	}

	if ctxJSON.Valid && ctxJSON.String != "" {
		var sc SessionContext
		if err := json.Unmarshal([]byte(ctxJSON.String), &sc); err != nil {
			return nil, fmt.Errorf("unmarshal context: %w", err)
		}
		s.Context = &sc
	}

	s.Metadata = make(map[string]string)
	if metaJSON.Valid && metaJSON.String != "" {
		if err := json.Unmarshal([]byte(metaJSON.String), &s.Metadata); err != nil {
			return nil, fmt.Errorf("unmarshal metadata: %w", err)
		}
	}

	return &s, nil
}

// updateSessionStatus updates the status and updated_at of a session.
func updateSessionStatus(db *sql.DB, id string, status Status, now time.Time) error {
	res, err := db.Exec(
		`UPDATE sessions SET status = ?, updated_at = ? WHERE id = ?`,
		string(status), now.Unix(), id,
	)
	if err != nil {
		return fmt.Errorf("update session status: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("update session status: %w", sql.ErrNoRows)
	}
	return nil
}

// updateSessionResumed sets the resumed_at and status to active.
func updateSessionResumed(db *sql.DB, id string, now time.Time) error {
	res, err := db.Exec(
		`UPDATE sessions SET status = ?, updated_at = ?, resumed_at = ? WHERE id = ?`,
		string(StatusActive), now.Unix(), now.Unix(), id,
	)
	if err != nil {
		return fmt.Errorf("update session resumed: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("update session resumed: %w", sql.ErrNoRows)
	}
	return nil
}

// updateSessionFailed sets the status to failed with error info.
func updateSessionFailed(db *sql.DB, id string, errorInfo string, now time.Time) error {
	res, err := db.Exec(
		`UPDATE sessions SET status = ?, error_info = ?, updated_at = ? WHERE id = ?`,
		string(StatusFailed), errorInfo, now.Unix(), id,
	)
	if err != nil {
		return fmt.Errorf("update session failed: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("update session failed: %w", sql.ErrNoRows)
	}
	return nil
}

// updateSessionContext updates the context JSON of a session.
func updateSessionContext(db *sql.DB, id string, sc *SessionContext, now time.Time) error {
	ctxJSON, err := json.Marshal(sc)
	if err != nil {
		return fmt.Errorf("marshal context: %w", err)
	}
	_, err = db.Exec(
		`UPDATE sessions SET context = ?, updated_at = ? WHERE id = ?`,
		string(ctxJSON), now.Unix(), id,
	)
	if err != nil {
		return fmt.Errorf("update session context: %w", err)
	}
	return nil
}

// selectSessions lists sessions with optional device and status filters.
func selectSessions(db *sql.DB, deviceID string, statusFilter Status, limit int) ([]Session, error) {
	query := `SELECT id, device_id, status, created_at, updated_at, resumed_at, context, error_info, metadata FROM sessions WHERE 1=1`
	args := make([]any, 0, 3)

	if deviceID != "" {
		query += ` AND device_id = ?`
		args = append(args, deviceID)
	}
	if statusFilter != "" {
		query += ` AND status = ?`
		args = append(args, string(statusFilter))
	}

	query += ` ORDER BY updated_at DESC`

	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("select sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var sessions []Session
	for rows.Next() {
		var (
			s         Session
			createdAt int64
			updatedAt int64
			resumedAt sql.NullInt64
			ctxJSON   sql.NullString
			metaJSON  sql.NullString
			statusStr string
		)

		if err := rows.Scan(
			&s.ID, &s.DeviceID, &statusStr,
			&createdAt, &updatedAt, &resumedAt,
			&ctxJSON, &s.ErrorInfo, &metaJSON,
		); err != nil {
			return nil, fmt.Errorf("scan sessions row: %w", err)
		}

		s.Status = Status(statusStr)
		s.CreatedAt = time.Unix(createdAt, 0)
		s.UpdatedAt = time.Unix(updatedAt, 0)

		if resumedAt.Valid {
			t := time.Unix(resumedAt.Int64, 0)
			s.ResumedAt = &t
		}

		if ctxJSON.Valid && ctxJSON.String != "" {
			var sc SessionContext
			if err := json.Unmarshal([]byte(ctxJSON.String), &sc); err != nil {
				return nil, fmt.Errorf("unmarshal context: %w", err)
			}
			s.Context = &sc
		}

		s.Metadata = make(map[string]string)
		if metaJSON.Valid && metaJSON.String != "" {
			if err := json.Unmarshal([]byte(metaJSON.String), &s.Metadata); err != nil {
				return nil, fmt.Errorf("unmarshal metadata: %w", err)
			}
		}

		sessions = append(sessions, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sessions: %w", err)
	}
	return sessions, nil
}

// deleteSession deletes a session and its related events and checkpoints.
func deleteSession(db *sql.DB, id string) error {
	// Enable foreign keys for cascade delete.
	if _, err := db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		return fmt.Errorf("enable foreign keys: %w", err)
	}
	res, err := db.Exec(`DELETE FROM sessions WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("delete session: %w", sql.ErrNoRows)
	}
	return nil
}

// insertEvent inserts a session event, computing the next sequence number.
func insertEvent(db *sql.DB, sessionID, eventType string, data []byte, now time.Time) error {
	var maxSeq sql.NullInt64
	err := db.QueryRow(
		`SELECT MAX(sequence) FROM session_events WHERE session_id = ?`, sessionID,
	).Scan(&maxSeq)
	if err != nil {
		return fmt.Errorf("query max sequence: %w", err)
	}

	seq := 1
	if maxSeq.Valid {
		seq = int(maxSeq.Int64) + 1
	}

	_, err = db.Exec(
		`INSERT INTO session_events (session_id, timestamp, event_type, data, sequence)
		 VALUES (?, ?, ?, ?, ?)`,
		sessionID, now.Unix(), eventType, data, seq,
	)
	if err != nil {
		return fmt.Errorf("insert event: %w", err)
	}
	return nil
}

// selectRecentEvents returns the most recent events for a session, ordered by sequence.
func selectRecentEvents(db *sql.DB, sessionID string, limit int) ([]Event, error) {
	rows, err := db.Query(
		`SELECT id, session_id, timestamp, event_type, data, sequence
		 FROM session_events WHERE session_id = ?
		 ORDER BY sequence DESC LIMIT ?`,
		sessionID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("select recent events: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var events []Event
	for rows.Next() {
		var e Event
		var ts int64
		if err := rows.Scan(&e.ID, &e.SessionID, &ts, &e.Type, &e.Data, &e.Sequence); err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}
		e.Timestamp = time.Unix(ts, 0)
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate events: %w", err)
	}

	// Reverse to get ascending order.
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}
	return events, nil
}

// insertCheckpoint inserts a session checkpoint.
func insertCheckpoint(db *sql.DB, sessionID, description string, state *SessionContext, now time.Time) (*Checkpoint, error) {
	stateJSON, err := json.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("marshal checkpoint state: %w", err)
	}

	res, err := db.Exec(
		`INSERT INTO session_checkpoints (session_id, timestamp, state, description)
		 VALUES (?, ?, ?, ?)`,
		sessionID, now.Unix(), string(stateJSON), description,
	)
	if err != nil {
		return nil, fmt.Errorf("insert checkpoint: %w", err)
	}

	id, _ := res.LastInsertId()
	return &Checkpoint{
		ID:          id,
		SessionID:   sessionID,
		Timestamp:   now,
		State:       state,
		Description: description,
	}, nil
}

// selectLastCheckpoint returns the most recent checkpoint for a session.
func selectLastCheckpoint(db *sql.DB, sessionID string) (*Checkpoint, error) {
	row := db.QueryRow(
		`SELECT id, session_id, timestamp, state, description
		 FROM session_checkpoints WHERE session_id = ?
		 ORDER BY timestamp DESC LIMIT 1`,
		sessionID,
	)

	var (
		c        Checkpoint
		ts       int64
		stateStr string
	)
	err := row.Scan(&c.ID, &c.SessionID, &ts, &stateStr, &c.Description)
	if err != nil {
		return nil, fmt.Errorf("scan checkpoint: %w", err)
	}

	c.Timestamp = time.Unix(ts, 0)
	var sc SessionContext
	if err := json.Unmarshal([]byte(stateStr), &sc); err != nil {
		return nil, fmt.Errorf("unmarshal checkpoint state: %w", err)
	}
	c.State = &sc

	return &c, nil
}

// markActiveAsInterrupted sets all active sessions to interrupted.
func markActiveAsInterrupted(db *sql.DB, now time.Time) (int64, error) {
	res, err := db.Exec(
		`UPDATE sessions SET status = ?, updated_at = ? WHERE status = ?`,
		string(StatusInterrupted), now.Unix(), string(StatusActive),
	)
	if err != nil {
		return 0, fmt.Errorf("mark active as interrupted: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// selectActiveSessionIDs returns all session IDs with active status.
func selectActiveSessionIDs(db *sql.DB) ([]string, error) {
	rows, err := db.Query(
		`SELECT id FROM sessions WHERE status = ?`, string(StatusActive),
	)
	if err != nil {
		return nil, fmt.Errorf("select active sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan session id: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
