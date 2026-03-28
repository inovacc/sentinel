package session

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Status represents the state of a session.
type Status string

const (
	StatusActive      Status = "active"
	StatusPaused      Status = "paused"
	StatusCompleted   Status = "completed"
	StatusFailed      Status = "failed"
	StatusInterrupted Status = "interrupted"
)

// Session represents an active interaction with a remote device.
type Session struct {
	ID        string
	DeviceID  string
	Status    Status
	CreatedAt time.Time
	UpdatedAt time.Time
	ResumedAt *time.Time
	Context   *SessionContext
	ErrorInfo string
	Metadata  map[string]string
}

// SessionContext captures the state needed to resume a session.
type SessionContext struct {
	WorkingDir   string            `json:"working_dir"`
	Env          map[string]string `json:"env"`
	LastCommand  string            `json:"last_command"`
	LastOutput   string            `json:"last_output"`
	LastExitCode int               `json:"last_exit_code"`
	ProjectName  string            `json:"project_name"`
}

// Event records a session event for audit and resumption.
type Event struct {
	ID        int64
	SessionID string
	Timestamp time.Time
	Type      string // "command", "output", "error", "checkpoint", "state_change"
	Data      []byte
	Sequence  int
}

// Checkpoint is a snapshot of session state at a point in time.
type Checkpoint struct {
	ID          int64
	SessionID   string
	Timestamp   time.Time
	State       *SessionContext
	Description string
}

// Manager handles session lifecycle with SQLite persistence.
type Manager struct {
	db *sql.DB
	mu sync.RWMutex
	// Active session heartbeat tracking.
	heartbeats map[string]time.Time
}

// NewManager creates a new session manager and runs schema migrations.
func NewManager(db *sql.DB) (*Manager, error) {
	if err := migrateSchema(db); err != nil {
		return nil, fmt.Errorf("session manager init: %w", err)
	}
	// Enable foreign keys for cascade deletes.
	if _, err := db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}
	return &Manager{
		db:         db,
		heartbeats: make(map[string]time.Time),
	}, nil
}

// Create creates a new session with an auto-generated UUID.
func (m *Manager) Create(ctx context.Context, deviceID, projectName, description, workingDir string, env map[string]string) (*Session, error) {
	now := time.Now()
	s := &Session{
		ID:        uuid.New().String(),
		DeviceID:  deviceID,
		Status:    StatusActive,
		CreatedAt: now,
		UpdatedAt: now,
		Context: &SessionContext{
			WorkingDir:  workingDir,
			Env:         env,
			ProjectName: projectName,
		},
		Metadata: map[string]string{
			"description": description,
		},
	}

	if err := insertSession(m.db, s); err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	m.mu.Lock()
	m.heartbeats[s.ID] = now
	m.mu.Unlock()

	return s, nil
}

// Resume resumes a paused or interrupted session, returning the session,
// its last checkpoint (if any), and recent events (up to 20).
func (m *Manager) Resume(ctx context.Context, sessionID string) (*Session, *Checkpoint, []Event, error) {
	s, err := selectSession(m.db, sessionID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("resume session: %w", err)
	}

	if s.Status != StatusPaused && s.Status != StatusInterrupted {
		return nil, nil, nil, fmt.Errorf("resume session: cannot resume session with status %q", s.Status)
	}

	now := time.Now()
	if err := updateSessionResumed(m.db, sessionID, now); err != nil {
		return nil, nil, nil, fmt.Errorf("resume session: %w", err)
	}

	s.Status = StatusActive
	s.UpdatedAt = now
	t := now
	s.ResumedAt = &t

	m.mu.Lock()
	m.heartbeats[sessionID] = now
	m.mu.Unlock()

	// Get last checkpoint (may not exist).
	cp, err := selectLastCheckpoint(m.db, sessionID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		// Checkpoint is optional; only fail on unexpected errors.
		if !isNoRows(err) {
			return nil, nil, nil, fmt.Errorf("resume session get checkpoint: %w", err)
		}
		cp = nil
	}

	// Get recent events.
	events, err := selectRecentEvents(m.db, sessionID, 20)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("resume session get events: %w", err)
	}

	return s, cp, events, nil
}

// isNoRows checks if the error wraps sql.ErrNoRows.
func isNoRows(err error) bool {
	return errors.Is(err, sql.ErrNoRows) || (err != nil && err.Error() == "scan checkpoint: sql: no rows in result set")
}

// Pause pauses a session and creates a checkpoint with the current state.
func (m *Manager) Pause(ctx context.Context, sessionID, reason string) (*Checkpoint, error) {
	s, err := selectSession(m.db, sessionID)
	if err != nil {
		return nil, fmt.Errorf("pause session: %w", err)
	}

	if s.Status != StatusActive {
		return nil, fmt.Errorf("pause session: cannot pause session with status %q", s.Status)
	}

	now := time.Now()
	if err := updateSessionStatus(m.db, sessionID, StatusPaused, now); err != nil {
		return nil, fmt.Errorf("pause session: %w", err)
	}

	cp, err := insertCheckpoint(m.db, sessionID, reason, s.Context, now)
	if err != nil {
		return nil, fmt.Errorf("pause session create checkpoint: %w", err)
	}

	m.mu.Lock()
	delete(m.heartbeats, sessionID)
	m.mu.Unlock()

	return cp, nil
}

// Complete marks a session as completed.
func (m *Manager) Complete(ctx context.Context, sessionID string) error {
	now := time.Now()
	if err := updateSessionStatus(m.db, sessionID, StatusCompleted, now); err != nil {
		return fmt.Errorf("complete session: %w", err)
	}

	m.mu.Lock()
	delete(m.heartbeats, sessionID)
	m.mu.Unlock()

	return nil
}

// Fail marks a session as failed with error info.
func (m *Manager) Fail(ctx context.Context, sessionID, errorInfo string) error {
	now := time.Now()
	if err := updateSessionFailed(m.db, sessionID, errorInfo, now); err != nil {
		return fmt.Errorf("fail session: %w", err)
	}

	m.mu.Lock()
	delete(m.heartbeats, sessionID)
	m.mu.Unlock()

	return nil
}

// Get retrieves a session by ID.
func (m *Manager) Get(ctx context.Context, sessionID string) (*Session, error) {
	s, err := selectSession(m.db, sessionID)
	if err != nil {
		return nil, fmt.Errorf("get session: %w", err)
	}
	return s, nil
}

// List returns sessions matching the optional filters.
// Pass empty deviceID or empty statusFilter to skip that filter.
func (m *Manager) List(ctx context.Context, deviceID string, statusFilter Status, limit int) ([]Session, error) {
	sessions, err := selectSessions(m.db, deviceID, statusFilter, limit)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	return sessions, nil
}

// Destroy deletes a session and all its related events and checkpoints.
func (m *Manager) Destroy(ctx context.Context, sessionID string) error {
	// Manually delete children first in case foreign keys are not enabled.
	if _, err := m.db.Exec(`DELETE FROM session_events WHERE session_id = ?`, sessionID); err != nil {
		return fmt.Errorf("destroy session events: %w", err)
	}
	if _, err := m.db.Exec(`DELETE FROM session_checkpoints WHERE session_id = ?`, sessionID); err != nil {
		return fmt.Errorf("destroy session checkpoints: %w", err)
	}
	if err := deleteSession(m.db, sessionID); err != nil {
		return fmt.Errorf("destroy session: %w", err)
	}

	m.mu.Lock()
	delete(m.heartbeats, sessionID)
	m.mu.Unlock()

	return nil
}

// AddEvent records an event for a session.
func (m *Manager) AddEvent(ctx context.Context, sessionID, eventType string, data []byte) error {
	now := time.Now()
	if err := insertEvent(m.db, sessionID, eventType, data, now); err != nil {
		return fmt.Errorf("add event: %w", err)
	}
	return nil
}

// CreateCheckpoint creates a checkpoint snapshot for a session.
func (m *Manager) CreateCheckpoint(ctx context.Context, sessionID, description string, state *SessionContext) (*Checkpoint, error) {
	now := time.Now()
	cp, err := insertCheckpoint(m.db, sessionID, description, state, now)
	if err != nil {
		return nil, fmt.Errorf("create checkpoint: %w", err)
	}
	return cp, nil
}

// Heartbeat updates the heartbeat timestamp for an active session.
func (m *Manager) Heartbeat(ctx context.Context, sessionID string) error {
	// Verify the session exists and is active.
	s, err := selectSession(m.db, sessionID)
	if err != nil {
		return fmt.Errorf("heartbeat: %w", err)
	}
	if s.Status != StatusActive {
		return fmt.Errorf("heartbeat: session %q is not active (status=%q)", sessionID, s.Status)
	}

	now := time.Now()
	m.mu.Lock()
	m.heartbeats[sessionID] = now
	m.mu.Unlock()

	// Also update updated_at in the database.
	if err := updateSessionStatus(m.db, sessionID, StatusActive, now); err != nil {
		return fmt.Errorf("heartbeat update: %w", err)
	}
	return nil
}

// RecoverInterrupted marks all active sessions as interrupted.
// This should be called on startup to handle sessions that were active
// when the process last exited. Returns the count of recovered sessions.
func (m *Manager) RecoverInterrupted(ctx context.Context) (int, error) {
	now := time.Now()
	n, err := markActiveAsInterrupted(m.db, now)
	if err != nil {
		return 0, fmt.Errorf("recover interrupted: %w", err)
	}

	m.mu.Lock()
	m.heartbeats = make(map[string]time.Time)
	m.mu.Unlock()

	return int(n), nil
}

// CheckStale finds active sessions whose last heartbeat exceeds the timeout
// and marks them as interrupted. Returns the count of stale sessions found.
func (m *Manager) CheckStale(ctx context.Context, timeout time.Duration) (int, error) {
	now := time.Now()
	cutoff := now.Add(-timeout)

	m.mu.RLock()
	var staleIDs []string
	for id, lastBeat := range m.heartbeats {
		if lastBeat.Before(cutoff) {
			staleIDs = append(staleIDs, id)
		}
	}
	m.mu.RUnlock()

	for _, id := range staleIDs {
		if err := updateSessionStatus(m.db, id, StatusInterrupted, now); err != nil {
			return 0, fmt.Errorf("check stale: mark session %q: %w", id, err)
		}
		m.mu.Lock()
		delete(m.heartbeats, id)
		m.mu.Unlock()
	}

	return len(staleIDs), nil
}
