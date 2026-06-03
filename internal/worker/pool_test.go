package worker

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/inovacc/sentinel/internal/sandbox"
	_ "modernc.org/sqlite"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestPool(t *testing.T, allow []string, opts ...Option) (*Pool, *sql.DB, string) {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	root := t.TempDir()
	sb, err := sandbox.New(sandbox.Config{Root: root, ExecAllowlist: allow, BlockedCommands: []string{"rm -rf /"}})
	if err != nil {
		t.Fatalf("sandbox.New: %v", err)
	}
	opts = append([]Option{WithLogger(quietLogger())}, opts...)
	p, err := NewPool(db, sb, opts...)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(p.Stop)
	return p, db, root
}

func writeSleeper(t *testing.T, root string, seconds int) {
	t.Helper()
	src := fmt.Sprintf("package main\nimport \"time\"\nfunc main() { time.Sleep(%d * time.Second) }\n", seconds)
	if err := os.WriteFile(filepath.Join(root, "sleeper.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
}

func waitStatus(t *testing.T, p *Pool, id string, want Status, within time.Duration) *Worker {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		w, err := p.Get(id)
		if err == nil && w.Status == want {
			return w
		}
		if time.Now().After(deadline) {
			got := "<get error>"
			if w != nil {
				got = string(w.Status)
			}
			t.Fatalf("worker %s did not reach %s within %s (last=%s)", id, want, within, got)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestSpawn_NonAllowlistedRefused(t *testing.T) {
	p, _, _ := newTestPool(t, []string{"go"})
	_, err := p.Spawn(context.Background(), "not-allowed", nil, "", nil, "", nil, 0)
	if err == nil {
		t.Fatal("a non-allowlisted command must be refused before spawning")
	}
}

func TestSpawn_CompletesAndPersists(t *testing.T) {
	p, _, _ := newTestPool(t, []string{"go"})
	w, err := p.Spawn(context.Background(), "go", []string{"version"}, "", nil, "sess-1", map[string]string{"k": "v"}, 0)
	if err != nil {
		t.Fatalf("Spawn: %v", err)
	}
	if w.Status != StatusRunning {
		t.Errorf("freshly spawned status = %s, want running", w.Status)
	}
	done := waitStatus(t, p, w.ID, StatusCompleted, 30*time.Second)
	if done.ExitCode != 0 {
		t.Errorf("exit = %d, want 0 (stderr=%s)", done.ExitCode, done.Stderr)
	}
	if !strings.Contains(done.Stdout, "go version") {
		t.Errorf("stdout = %q, want to contain 'go version'", done.Stdout)
	}

	// List (merges memory + DB) and status filter.
	all, err := p.List("")
	if err != nil || len(all) != 1 {
		t.Fatalf("List() = %d workers, %v; want 1", len(all), err)
	}
	if got, _ := p.List(StatusFailed); len(got) != 0 {
		t.Errorf("List(failed) = %d, want 0", len(got))
	}
}

func TestGet_NotFound(t *testing.T) {
	p, _, _ := newTestPool(t, []string{"go"})
	if _, err := p.Get("nope"); err == nil {
		t.Fatal("Get of an unknown worker should error")
	}
}

func TestSpawn_MaxWorkersAndKill(t *testing.T) {
	p, _, root := newTestPool(t, []string{"go"}, WithMaxWorkers(1))
	writeSleeper(t, root, 5)

	w1, err := p.Spawn(context.Background(), "go", []string{"run", "sleeper.go"}, "", nil, "", nil, 0)
	if err != nil {
		t.Fatalf("first Spawn: %v", err)
	}
	if p.ActiveCount() != 1 {
		t.Fatalf("ActiveCount = %d, want 1", p.ActiveCount())
	}

	// Second spawn must be rejected by the max-workers limit.
	if _, err := p.Spawn(context.Background(), "go", []string{"run", "sleeper.go"}, "", nil, "", nil, 0); err == nil {
		t.Error("second spawn should be rejected at max workers")
	} else if !strings.Contains(err.Error(), "max workers") {
		t.Errorf("error = %v, want max-workers rejection", err)
	}

	if err := p.Kill(w1.ID); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	got, _ := p.Get(w1.ID)
	if got.Status != StatusKilled {
		t.Errorf("after Kill status = %s, want killed", got.Status)
	}
	// Killing a non-running worker errors.
	if err := p.Kill(w1.ID); err == nil {
		t.Error("killing an already-killed worker should error")
	}
	if p.ActiveCount() != 0 {
		t.Errorf("ActiveCount after kill = %d, want 0", p.ActiveCount())
	}
}

func TestKillAll(t *testing.T) {
	p, _, root := newTestPool(t, []string{"go"}, WithMaxWorkers(5))
	writeSleeper(t, root, 5)
	for i := range 2 {
		if _, err := p.Spawn(context.Background(), "go", []string{"run", "sleeper.go"}, "", nil, "", nil, 0); err != nil {
			t.Fatalf("Spawn %d: %v", i, err)
		}
	}
	if p.TotalCount() != 2 {
		t.Errorf("TotalCount = %d, want 2", p.TotalCount())
	}
	killed, err := p.KillAll()
	if err != nil {
		t.Fatalf("KillAll: %v", err)
	}
	if killed != 2 {
		t.Errorf("KillAll killed %d, want 2", killed)
	}
	if p.ActiveCount() != 0 {
		t.Errorf("ActiveCount after KillAll = %d, want 0", p.ActiveCount())
	}
}

// TestCrashRecovery verifies that workers left "running" in the DB (a daemon
// crash) are marked stale on the next NewPool, and are reachable via the DB path.
func TestCrashRecovery(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sb, err := sandbox.New(sandbox.Config{Root: t.TempDir(), ExecAllowlist: []string{"go"}})
	if err != nil {
		t.Fatalf("sandbox: %v", err)
	}

	p1, err := NewPool(db, sb, WithLogger(quietLogger()))
	if err != nil {
		t.Fatalf("NewPool 1: %v", err)
	}
	w, err := p1.Spawn(context.Background(), "go", []string{"version"}, "", nil, "", nil, 0)
	if err != nil {
		t.Fatalf("Spawn: %v", err)
	}
	waitStatus(t, p1, w.ID, StatusCompleted, 30*time.Second)
	p1.Stop()

	// Simulate a crash: the row is left as "running".
	if _, err := db.Exec(`UPDATE workers SET status = 'running' WHERE id = ?`, w.ID); err != nil {
		t.Fatalf("seed running: %v", err)
	}

	p2, err := NewPool(db, sb, WithLogger(quietLogger()))
	if err != nil {
		t.Fatalf("NewPool 2: %v", err)
	}
	t.Cleanup(p2.Stop)

	// p2 has no in-memory worker, so Get reads from the DB and reflects the
	// startup stale-recovery sweep.
	got, err := p2.Get(w.ID)
	if err != nil {
		t.Fatalf("Get from DB after recovery: %v", err)
	}
	if got.Status != StatusStale {
		t.Errorf("recovered worker status = %s, want stale", got.Status)
	}
}
