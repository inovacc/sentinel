package supervisor

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"time"

	"github.com/inovacc/sentinel/internal/svcutil"
)

const envRole = "SENTINEL_ROLE"

// Option configures a Supervisor.
type Option func(*Supervisor)

// Supervisor manages the monitor/worker process lifecycle.
// The monitor process spawns and supervises a worker subprocess,
// restarting it on crashes with configurable backoff.
type Supervisor struct {
	logger       *slog.Logger
	maxRestarts  int
	restartDelay time.Duration
	workerFunc   func(ctx context.Context) int
}

// New creates a Supervisor with sensible defaults.
func New(logger *slog.Logger, workerFunc func(ctx context.Context) int, opts ...Option) *Supervisor {
	s := &Supervisor{
		logger:       logger,
		maxRestarts:  10,
		restartDelay: 2 * time.Second,
		workerFunc:   workerFunc,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// WithMaxRestarts sets the maximum number of consecutive worker restarts
// before the monitor gives up.
func WithMaxRestarts(n int) Option {
	return func(s *Supervisor) {
		s.maxRestarts = n
	}
}

// WithRestartDelay sets the base delay between worker restarts.
func WithRestartDelay(d time.Duration) Option {
	return func(s *Supervisor) {
		s.restartDelay = d
	}
}

// Run detects the current role and dispatches to monitor or worker mode.
// Returns the process exit code.
func (s *Supervisor) Run(ctx context.Context) int {
	role := os.Getenv(envRole)
	switch role {
	case "worker":
		return s.runWorker(ctx)
	default:
		return s.runMonitor(ctx)
	}
}

// runMonitor spawns the worker as a subprocess and supervises it.
func (s *Supervisor) runMonitor(ctx context.Context) int {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Catch termination signals so we can forward them to the worker.
	sigCh := make(chan os.Signal, 1)
	registerSignals(sigCh)
	defer signal.Stop(sigCh)

	selfPath, err := os.Executable()
	if err != nil {
		s.logger.Error("failed to resolve executable path", "error", err)
		return svcutil.ExitError
	}

	restarts := 0

	for {
		s.logger.Info("spawning worker process", "attempt", restarts+1, "max_restarts", s.maxRestarts)

		cmd := exec.CommandContext(ctx, selfPath, os.Args[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		cmd.Env = append(os.Environ(), fmt.Sprintf("%s=worker", envRole))

		if err := cmd.Start(); err != nil {
			s.logger.Error("failed to start worker", "error", err)
			return svcutil.ExitError
		}

		// Forward signals to the worker in a goroutine.
		done := make(chan struct{})
		go func() {
			select {
			case sig := <-sigCh:
				s.logger.Info("forwarding signal to worker", "signal", sig)
				if cmd.Process != nil {
					signalProcess(cmd.Process, sig)
				}
			case <-done:
			}
		}()

		exitCode := waitExitCode(cmd)
		close(done)

		s.logger.Info("worker exited", "exit_code", exitCode)

		switch exitCode {
		case svcutil.ExitOK:
			return svcutil.ExitOK
		case svcutil.ExitUpgrade:
			s.logger.Info("worker requested upgrade, exiting monitor")
			return svcutil.ExitUpgrade
		case svcutil.ExitRestart:
			s.logger.Info("worker requested restart, restarting immediately")
			restarts = 0
			continue
		default:
			restarts++
			if restarts > s.maxRestarts {
				s.logger.Error("max restarts exceeded, giving up", "restarts", restarts)
				return svcutil.ExitError
			}
			s.logger.Warn("worker crashed, restarting after delay",
				"exit_code", exitCode,
				"restart_count", restarts,
				"delay", s.restartDelay,
			)
		}

		// Check if context was cancelled during the delay.
		select {
		case <-ctx.Done():
			s.logger.Info("context cancelled, stopping monitor")
			return svcutil.ExitOK
		case <-time.After(s.restartDelay):
		}
	}
}

// runWorker calls the worker function, catching panics.
func (s *Supervisor) runWorker(ctx context.Context) int {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	registerSignals(sigCh)
	defer signal.Stop(sigCh)

	go func() {
		select {
		case sig := <-sigCh:
			s.logger.Info("worker received signal, shutting down", "signal", sig)
			cancel()
		case <-ctx.Done():
		}
	}()

	return s.safeRun(ctx)
}

// safeRun executes the worker function and recovers from panics.
func (s *Supervisor) safeRun(ctx context.Context) (code int) {
	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			s.logger.Error("worker panicked", "panic", r, "stack", string(buf[:n]))
			code = svcutil.ExitError
		}
	}()
	return s.workerFunc(ctx)
}

// waitExitCode waits for the command to finish and returns its exit code.
func waitExitCode(cmd *exec.Cmd) int {
	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		return svcutil.ExitError
	}
	return svcutil.ExitOK
}
