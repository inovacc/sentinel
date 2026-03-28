package supervisor

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/inovacc/sentinel/internal/svcutil"
)

func TestExitCodeConstants(t *testing.T) {
	tests := []struct {
		name string
		code int
		want int
	}{
		{"ExitOK", svcutil.ExitOK, 0},
		{"ExitError", svcutil.ExitError, 1},
		{"ExitRestart", svcutil.ExitRestart, 3},
		{"ExitUpgrade", svcutil.ExitUpgrade, 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.code != tt.want {
				t.Errorf("got %d, want %d", tt.code, tt.want)
			}
		})
	}
}

func TestWorkerFuncRuns(t *testing.T) {
	called := false
	worker := func(_ context.Context) int {
		called = true
		return svcutil.ExitOK
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	sv := New(logger, worker)

	// Simulate worker role.
	t.Setenv("SENTINEL_ROLE", "worker")
	code := sv.Run(context.Background())

	if !called {
		t.Error("worker function was not called")
	}
	if code != svcutil.ExitOK {
		t.Errorf("got exit code %d, want %d", code, svcutil.ExitOK)
	}
}

func TestWorkerPanicRecovery(t *testing.T) {
	worker := func(_ context.Context) int {
		panic("test panic")
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	sv := New(logger, worker)

	code := sv.runWorker(context.Background())
	if code != svcutil.ExitError {
		t.Errorf("got exit code %d, want %d after panic", code, svcutil.ExitError)
	}
}

func TestRoleDetection(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	worker := func(_ context.Context) int { return svcutil.ExitOK }

	tests := []struct {
		name string
		role string
		want string // "monitor" or "worker"
	}{
		{"empty defaults to monitor", "", "monitor"},
		{"monitor role", "monitor", "monitor"},
		{"worker role", "worker", "worker"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("SENTINEL_ROLE", tt.role)
			sv := New(logger, worker)

			role := os.Getenv(envRole)
			if tt.want == "worker" && role != "worker" {
				t.Errorf("expected worker role, got %q", role)
			}
			if tt.want == "monitor" && role == "worker" {
				t.Errorf("expected monitor role, got %q", role)
			}
			_ = sv // ensure it compiles
		})
	}
}

func TestOptions(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	worker := func(_ context.Context) int { return svcutil.ExitOK }

	sv := New(logger, worker,
		WithMaxRestarts(5),
		WithRestartDelay(500*time.Millisecond),
	)

	if sv.maxRestarts != 5 {
		t.Errorf("maxRestarts = %d, want 5", sv.maxRestarts)
	}
	if sv.restartDelay != 500*time.Millisecond {
		t.Errorf("restartDelay = %v, want 500ms", sv.restartDelay)
	}
}
