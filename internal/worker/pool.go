// Package worker manages a pool of parallel task workers on a machine.
package worker

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	osexec "os/exec"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/inovacc/sentinel/internal/sandbox"
)

// Status represents the state of a worker.
type Status string

const (
	StatusRunning   Status = "running"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
	StatusKilled    Status = "killed"
	StatusStale     Status = "stale"
)

// Worker represents a running or completed task.
type Worker struct {
	ID         string            `json:"id"`
	Command    string            `json:"command"`
	Args       []string          `json:"args"`
	PID        int               `json:"pid"`
	Status     Status            `json:"status"`
	CreatedAt  time.Time         `json:"created_at"`
	StartedAt  time.Time         `json:"started_at"`
	FinishedAt *time.Time        `json:"finished_at,omitempty"`
	Stdout     string            `json:"stdout"`
	Stderr     string            `json:"stderr"`
	ExitCode   int               `json:"exit_code"`
	SessionID  string            `json:"session_id,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// DurationMs returns how long the worker has been running (or ran).
func (w *Worker) DurationMs() int64 {
	end := time.Now()
	if w.FinishedAt != nil {
		end = *w.FinishedAt
	}
	return end.Sub(w.StartedAt).Milliseconds()
}

// Option configures the pool.
type Option func(*Pool)

// WithMaxWorkers sets the max concurrent workers.
func WithMaxWorkers(n int) Option { return func(p *Pool) { p.maxWorkers = n } }

// WithStaleTimeout sets the auto-kill timeout for stale workers.
func WithStaleTimeout(d time.Duration) Option { return func(p *Pool) { p.staleTimeout = d } }

// WithLogger sets the logger.
func WithLogger(l *slog.Logger) Option { return func(p *Pool) { p.logger = l } }

// Pool manages worker processes.
type Pool struct {
	mu           sync.RWMutex
	workers      map[string]*activeWorker
	db           *sql.DB
	sandbox      *sandbox.Sandbox
	maxWorkers   int
	staleTimeout time.Duration
	logger       *slog.Logger
	cancel       context.CancelFunc
	done         chan struct{}
}

type activeWorker struct {
	Worker
	cmd    *osexec.Cmd
	stdout *bytes.Buffer
	stderr *bytes.Buffer
}

// NewPool creates a worker pool.
func NewPool(db *sql.DB, sb *sandbox.Sandbox, opts ...Option) (*Pool, error) {
	p := &Pool{
		workers:      make(map[string]*activeWorker),
		db:           db,
		sandbox:      sb,
		maxWorkers:   10,
		staleTimeout: 5 * time.Minute,
		logger:       slog.Default(),
		done:         make(chan struct{}),
	}
	for _, o := range opts {
		o(p)
	}

	if err := p.migrate(); err != nil {
		return nil, fmt.Errorf("worker: migrate: %w", err)
	}

	// Mark any previously running workers as stale (crash recovery).
	_, _ = p.db.Exec(`UPDATE workers SET status = ? WHERE status = ?`, string(StatusStale), string(StatusRunning))

	// Start reaper goroutine.
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	go p.reaper(ctx)

	return p, nil
}

// Spawn starts a new worker process.
func (p *Pool) Spawn(ctx context.Context, command string, args []string, workDir string, env map[string]string, sessionID string, metadata map[string]string, timeout time.Duration) (*Worker, error) {
	if err := p.sandbox.CheckExec(command, args); err != nil {
		return nil, fmt.Errorf("worker: %w", err)
	}

	p.mu.RLock()
	activeCount := 0
	for _, w := range p.workers {
		if w.Status == StatusRunning {
			activeCount++
		}
	}
	p.mu.RUnlock()

	if activeCount >= p.maxWorkers {
		return nil, fmt.Errorf("worker: max workers reached (%d)", p.maxWorkers)
	}

	id := uuid.New().String()[:8]
	now := time.Now()

	// Build command with background context — workers outlive the RPC call.
	cmd := osexec.Command(command, args...)
	if workDir != "" {
		resolved, err := p.sandbox.ResolvePath(workDir)
		if err != nil {
			return nil, fmt.Errorf("worker: resolve dir: %w", err)
		}
		cmd.Dir = resolved
	} else {
		cmd.Dir = p.sandbox.Root()
	}

	cmdEnv := os.Environ()
	for k, v := range env {
		cmdEnv = append(cmdEnv, k+"="+v)
	}
	cmd.Env = cmdEnv

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("worker: start: %w", err)
	}

	aw := &activeWorker{
		Worker: Worker{
			ID:        id,
			Command:   command,
			Args:      args,
			PID:       cmd.Process.Pid,
			Status:    StatusRunning,
			CreatedAt: now,
			StartedAt: now,
			ExitCode:  -1,
			SessionID: sessionID,
			Metadata:  metadata,
		},
		cmd:    cmd,
		stdout: &stdoutBuf,
		stderr: &stderrBuf,
	}

	p.mu.Lock()
	p.workers[id] = aw
	p.mu.Unlock()

	// Persist to DB.
	p.insertWorker(&aw.Worker)

	p.logger.Info("worker spawned", "id", id, "pid", cmd.Process.Pid, "command", command+" "+strings.Join(args, " "))

	// Monitor in background.
	go p.monitor(aw, timeout)

	return &aw.Worker, nil
}

// List returns all workers, optionally filtered by status.
func (p *Pool) List(statusFilter Status) ([]Worker, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Sync stdout/stderr from buffers for running workers.
	var result []Worker
	for _, aw := range p.workers {
		w := aw.Worker
		if aw.Status == StatusRunning {
			w.Stdout = aw.stdout.String()
			w.Stderr = aw.stderr.String()
		}
		if statusFilter == "" || w.Status == statusFilter {
			result = append(result, w)
		}
	}

	// Also get historical workers from DB.
	dbWorkers, err := p.listFromDB(statusFilter)
	if err != nil {
		return result, nil // Return in-memory on DB error.
	}

	// Merge: skip DB entries that are already in memory.
	existing := make(map[string]bool, len(result))
	for _, w := range result {
		existing[w.ID] = true
	}
	for _, w := range dbWorkers {
		if !existing[w.ID] {
			result = append(result, w)
		}
	}

	return result, nil
}

// Get returns a single worker.
func (p *Pool) Get(workerID string) (*Worker, error) {
	p.mu.RLock()
	aw, ok := p.workers[workerID]
	p.mu.RUnlock()

	if ok {
		w := aw.Worker
		if aw.Status == StatusRunning {
			w.Stdout = aw.stdout.String()
			w.Stderr = aw.stderr.String()
		}
		return &w, nil
	}

	// Check DB.
	return p.getFromDB(workerID)
}

// Kill terminates a running worker.
func (p *Pool) Kill(workerID string) error {
	p.mu.Lock()
	aw, ok := p.workers[workerID]
	p.mu.Unlock()

	if !ok {
		return fmt.Errorf("worker %s not found", workerID)
	}
	if aw.Status != StatusRunning {
		return fmt.Errorf("worker %s is not running (status: %s)", workerID, aw.Status)
	}

	if aw.cmd.Process != nil {
		_ = aw.cmd.Process.Kill()
	}

	p.mu.Lock()
	now := time.Now()
	aw.Status = StatusKilled
	aw.FinishedAt = &now
	aw.Stdout = aw.stdout.String()
	aw.Stderr = aw.stderr.String()
	p.mu.Unlock()

	p.updateWorker(&aw.Worker)
	p.logger.Info("worker killed", "id", workerID, "pid", aw.PID)
	return nil
}

// KillAll terminates all running workers.
func (p *Pool) KillAll() (int, error) {
	p.mu.RLock()
	var toKill []string
	for id, aw := range p.workers {
		if aw.Status == StatusRunning {
			toKill = append(toKill, id)
		}
	}
	p.mu.RUnlock()

	killed := 0
	for _, id := range toKill {
		if err := p.Kill(id); err == nil {
			killed++
		}
	}
	return killed, nil
}

// ActiveCount returns the number of running workers.
func (p *Pool) ActiveCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	count := 0
	for _, aw := range p.workers {
		if aw.Status == StatusRunning {
			count++
		}
	}
	return count
}

// TotalCount returns the total number of tracked workers (in memory).
func (p *Pool) TotalCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.workers)
}

// Stop stops the reaper and kills all running workers.
func (p *Pool) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
	_, _ = p.KillAll()
	<-p.done
}

// monitor waits for a worker to finish and updates its state.
func (p *Pool) monitor(aw *activeWorker, timeout time.Duration) {
	var ctx context.Context
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), timeout)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- aw.cmd.Wait()
	}()

	select {
	case err := <-done:
		now := time.Now()
		p.mu.Lock()
		aw.FinishedAt = &now
		aw.Stdout = aw.stdout.String()
		aw.Stderr = aw.stderr.String()
		if err != nil {
			if exitErr, ok := err.(*osexec.ExitError); ok {
				aw.ExitCode = exitErr.ExitCode()
			}
			aw.Status = StatusFailed
		} else {
			aw.ExitCode = 0
			aw.Status = StatusCompleted
		}
		p.mu.Unlock()
		p.updateWorker(&aw.Worker)
		p.logger.Info("worker finished", "id", aw.ID, "status", aw.Status, "exit_code", aw.ExitCode, "duration_ms", aw.DurationMs())

	case <-ctx.Done():
		// Timeout — kill.
		if aw.cmd.Process != nil {
			_ = aw.cmd.Process.Kill()
		}
		now := time.Now()
		p.mu.Lock()
		aw.Status = StatusStale
		aw.FinishedAt = &now
		aw.Stdout = aw.stdout.String()
		aw.Stderr = aw.stderr.String()
		p.mu.Unlock()
		p.updateWorker(&aw.Worker)
		p.logger.Warn("worker killed (timeout)", "id", aw.ID, "pid", aw.PID, "timeout", timeout)
	}
}

// reaper periodically checks for stale workers.
func (p *Pool) reaper(ctx context.Context) {
	defer close(p.done)
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.reap()
		}
	}
}

func (p *Pool) reap() {
	p.mu.RLock()
	var staleIDs []string
	for id, aw := range p.workers {
		if aw.Status == StatusRunning && time.Since(aw.StartedAt) > p.staleTimeout {
			staleIDs = append(staleIDs, id)
		}
	}
	p.mu.RUnlock()

	for _, id := range staleIDs {
		p.logger.Warn("reaping stale worker", "id", id)
		_ = p.Kill(id)
		p.mu.Lock()
		if aw, ok := p.workers[id]; ok {
			aw.Status = StatusStale
			p.updateWorker(&aw.Worker)
		}
		p.mu.Unlock()
	}
}

// --- SQLite persistence ---

func (p *Pool) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS workers (
    id          TEXT PRIMARY KEY,
    command     TEXT NOT NULL,
    args        TEXT DEFAULT '[]',
    pid         INTEGER NOT NULL,
    status      TEXT NOT NULL DEFAULT 'running',
    created_at  INTEGER NOT NULL,
    started_at  INTEGER NOT NULL,
    finished_at INTEGER,
    stdout      TEXT DEFAULT '',
    stderr      TEXT DEFAULT '',
    exit_code   INTEGER DEFAULT -1,
    session_id  TEXT DEFAULT '',
    metadata    TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_workers_status ON workers(status);
`
	_, err := p.db.Exec(schema)
	return err
}

func (p *Pool) insertWorker(w *Worker) {
	argsJSON, _ := json.Marshal(w.Args)
	metaJSON, _ := json.Marshal(w.Metadata)
	_, _ = p.db.Exec(
		`INSERT OR REPLACE INTO workers (id, command, args, pid, status, created_at, started_at, finished_at, stdout, stderr, exit_code, session_id, metadata)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		w.ID, w.Command, string(argsJSON), w.PID, string(w.Status),
		w.CreatedAt.Unix(), w.StartedAt.Unix(), nil,
		w.Stdout, w.Stderr, w.ExitCode, w.SessionID, string(metaJSON),
	)
}

func (p *Pool) updateWorker(w *Worker) {
	var finishedAt *int64
	if w.FinishedAt != nil {
		ts := w.FinishedAt.Unix()
		finishedAt = &ts
	}
	_, _ = p.db.Exec(
		`UPDATE workers SET status = ?, finished_at = ?, stdout = ?, stderr = ?, exit_code = ? WHERE id = ?`,
		string(w.Status), finishedAt, w.Stdout, w.Stderr, w.ExitCode, w.ID,
	)
}

func (p *Pool) listFromDB(statusFilter Status) ([]Worker, error) {
	var rows *sql.Rows
	var err error
	if statusFilter != "" {
		rows, err = p.db.Query(`SELECT id, command, args, pid, status, created_at, started_at, finished_at, stdout, stderr, exit_code, session_id, metadata FROM workers WHERE status = ? ORDER BY created_at DESC LIMIT 100`, string(statusFilter))
	} else {
		rows, err = p.db.Query(`SELECT id, command, args, pid, status, created_at, started_at, finished_at, stdout, stderr, exit_code, session_id, metadata FROM workers ORDER BY created_at DESC LIMIT 100`)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var workers []Worker
	for rows.Next() {
		w, err := scanWorkerRow(rows)
		if err != nil {
			continue
		}
		workers = append(workers, *w)
	}
	return workers, rows.Err()
}

func (p *Pool) getFromDB(id string) (*Worker, error) {
	row := p.db.QueryRow(`SELECT id, command, args, pid, status, created_at, started_at, finished_at, stdout, stderr, exit_code, session_id, metadata FROM workers WHERE id = ?`, id)

	var w Worker
	var argsJSON, metaJSON string
	var created, started int64
	var finished *int64
	err := row.Scan(&w.ID, &w.Command, &argsJSON, &w.PID, &w.Status, &created, &started, &finished, &w.Stdout, &w.Stderr, &w.ExitCode, &w.SessionID, &metaJSON)
	if err != nil {
		return nil, fmt.Errorf("worker %s not found: %w", id, err)
	}
	_ = json.Unmarshal([]byte(argsJSON), &w.Args)
	_ = json.Unmarshal([]byte(metaJSON), &w.Metadata)
	w.CreatedAt = time.Unix(created, 0)
	w.StartedAt = time.Unix(started, 0)
	if finished != nil {
		t := time.Unix(*finished, 0)
		w.FinishedAt = &t
	}
	return &w, nil
}

func scanWorkerRow(rows *sql.Rows) (*Worker, error) {
	var w Worker
	var argsJSON, metaJSON string
	var created, started int64
	var finished *int64
	err := rows.Scan(&w.ID, &w.Command, &argsJSON, &w.PID, &w.Status, &created, &started, &finished, &w.Stdout, &w.Stderr, &w.ExitCode, &w.SessionID, &metaJSON)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(argsJSON), &w.Args)
	_ = json.Unmarshal([]byte(metaJSON), &w.Metadata)
	w.CreatedAt = time.Unix(created, 0)
	w.StartedAt = time.Unix(started, 0)
	if finished != nil {
		t := time.Unix(*finished, 0)
		w.FinishedAt = &t
	}
	return &w, nil
}
