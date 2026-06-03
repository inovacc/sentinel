package exec

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	osexec "os/exec"
	"sync"
	"time"

	"github.com/inovacc/sentinel/internal/confine"
	"github.com/inovacc/sentinel/internal/sandbox"
)

// Runner executes commands within sandbox constraints.
type Runner struct {
	sandbox  *sandbox.Sandbox
	confiner confine.Confiner
	logger   *slog.Logger
	warnOnce sync.Once // guards the one-time "running unconfined" warning
}

// NewRunner creates a command runner with sandbox enforcement.
func NewRunner(sb *sandbox.Sandbox) *Runner {
	return &Runner{sandbox: sb}
}

// NewRunnerWithConfiner injects a confiner and logger (used by the daemon).
func NewRunnerWithConfiner(sb *sandbox.Sandbox, c confine.Confiner, logger *slog.Logger) *Runner {
	if logger == nil {
		logger = slog.Default()
	}
	return &Runner{sandbox: sb, confiner: c, logger: logger}
}

// applyConfine applies the confiner to a started process, returning an error
// when the platform supports confinement but it could not be applied
// (fail-closed). A nil confiner is a no-op, preserving legacy behavior.
func (r *Runner) applyConfine(p *os.Process) error {
	if r.confiner == nil {
		return nil // no confiner configured (e.g. legacy callers/tests)
	}
	err := r.confiner.Confine(p)
	refuse, warn := confine.Decide(r.confiner.Supported(), err)
	if warn && r.logger != nil {
		// Warn once per runner: on an unsupported platform this would otherwise
		// fire on every exec and flood the log.
		r.warnOnce.Do(func() {
			r.logger.Warn("exec: process is running unconfined (no OS sandbox on this platform)")
		})
	}
	if refuse {
		_ = p.Kill()
		// Reap the killed child so it does not linger as a zombie on Unix.
		// The caller returns immediately on error and never calls Wait, so
		// confinement enforcement owns cleanup of the process it refused.
		_, _ = p.Wait()
		return fmt.Errorf("exec: refusing unconfined process: %w", err)
	}
	return nil
}

// RunRequest describes a command to execute.
type RunRequest struct {
	Command    string
	Args       []string
	WorkingDir string // relative to sandbox root if not absolute
	Env        map[string]string
	Timeout    time.Duration
	Background bool // if true, start process and return immediately without waiting
}

// RunResult holds the output of a completed command.
type RunResult struct {
	ExitCode   int
	Stdout     string
	Stderr     string
	DurationMs int64
}

// Run executes a command and returns the captured result.
// If req.Background is true, starts the process detached and returns immediately.
func (r *Runner) Run(ctx context.Context, req *RunRequest) (*RunResult, error) {
	if req.Background {
		return r.runBackground(ctx, req)
	}

	if err := r.sandbox.CheckExec(req.Command, req.Args); err != nil {
		return nil, fmt.Errorf("exec: %w", err)
	}

	timeout := req.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd, err := r.buildCmd(ctx, req)
	if err != nil {
		return nil, err
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("exec: start command: %w", err)
	}
	if err := r.applyConfine(cmd.Process); err != nil {
		return nil, err
	}
	runErr := cmd.Wait()
	duration := time.Since(start).Milliseconds()

	result := &RunResult{
		Stdout:     stdout.String(),
		Stderr:     stderr.String(),
		DurationMs: duration,
	}

	if runErr != nil {
		if exitErr, ok := runErr.(*osexec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			return nil, fmt.Errorf("exec: run command: %w", runErr)
		}
	}

	return result, nil
}

// runBackground starts a process detached and returns immediately with its PID.
func (r *Runner) runBackground(ctx context.Context, req *RunRequest) (*RunResult, error) {
	if err := r.sandbox.CheckExec(req.Command, req.Args); err != nil {
		return nil, fmt.Errorf("exec: %w", err)
	}

	cmd, err := r.buildCmd(ctx, req)
	if err != nil {
		return nil, err
	}

	// Detach: don't capture stdout/stderr, let process run independently.
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("exec: start background: %w", err)
	}

	if err := r.applyConfine(cmd.Process); err != nil {
		return nil, err
	}

	pid := cmd.Process.Pid

	// Release the process so it's not killed when we return.
	_ = cmd.Process.Release()

	return &RunResult{
		Stdout:     fmt.Sprintf("started in background (PID %d)", pid),
		DurationMs: 0,
	}, nil
}

// RunStream executes a command and streams output via a callback.
func (r *Runner) RunStream(ctx context.Context, req *RunRequest, onOutput func(stream string, data []byte)) (*RunResult, error) {
	if err := r.sandbox.CheckExec(req.Command, req.Args); err != nil {
		return nil, fmt.Errorf("exec: %w", err)
	}

	timeout := req.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd, err := r.buildCmd(ctx, req)
	if err != nil {
		return nil, err
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("exec: stdout pipe: %w", err)
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("exec: stderr pipe: %w", err)
	}

	start := time.Now()
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("exec: start command: %w", err)
	}

	if err := r.applyConfine(cmd.Process); err != nil {
		return nil, err
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		streamPipe(stdoutPipe, "stdout", onOutput)
	}()

	go func() {
		defer wg.Done()
		streamPipe(stderrPipe, "stderr", onOutput)
	}()

	wg.Wait()
	runErr := cmd.Wait()
	duration := time.Since(start).Milliseconds()

	result := &RunResult{DurationMs: duration}

	if runErr != nil {
		if exitErr, ok := runErr.(*osexec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			return nil, fmt.Errorf("exec: wait command: %w", runErr)
		}
	}

	return result, nil
}

func (r *Runner) buildCmd(ctx context.Context, req *RunRequest) (*osexec.Cmd, error) {
	cmd := osexec.CommandContext(ctx, req.Command, req.Args...)

	// Resolve working directory.
	if req.WorkingDir != "" {
		resolved, err := r.sandbox.ResolvePath(req.WorkingDir)
		if err != nil {
			return nil, fmt.Errorf("exec: resolve working dir: %w", err)
		}
		cmd.Dir = resolved
	} else {
		cmd.Dir = r.sandbox.Root()
	}

	// Build environment: inherit current + merge request env.
	env := os.Environ()
	for k, v := range req.Env {
		env = append(env, k+"="+v)
	}
	cmd.Env = env

	if r.confiner != nil {
		if err := r.confiner.Prepare(cmd); err != nil {
			return nil, fmt.Errorf("exec: prepare confinement: %w", err)
		}
	}

	return cmd, nil
}

func streamPipe(pipe io.ReadCloser, name string, onOutput func(string, []byte)) {
	buf := make([]byte, 4096)
	for {
		n, err := pipe.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			onOutput(name, chunk)
		}
		if err != nil {
			break
		}
	}
}
