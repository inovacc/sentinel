// Package confine applies OS-level confinement to processes Sentinel spawns,
// layering host-enforced limits on top of the in-process sandbox allowlist.
package confine

import (
	"log/slog"
	"os"
	osexec "os/exec"
)

// Config controls process confinement limits.
type Config struct {
	Enabled      bool
	MaxMemoryMB  uint64
	CPUPercent   uint32
	MaxProcesses uint32
}

// DefaultConfig returns conservative-but-workable confinement limits.
func DefaultConfig() Config {
	return Config{Enabled: true, MaxMemoryMB: 1024, CPUPercent: 80, MaxProcesses: 64}
}

// Confiner applies OS-level confinement to spawned processes.
type Confiner interface {
	// Prepare configures confinement set at creation time (restricted token,
	// creation flags). Call before cmd.Start().
	Prepare(cmd *osexec.Cmd) error
	// Confine attaches post-creation limits (Job Object assignment). Call
	// immediately after cmd.Start().
	Confine(p *os.Process) error
	// Supported reports whether real confinement is in effect on this platform.
	Supported() bool
	// Close releases confiner-held OS handles.
	Close() error
}

// New builds the platform confiner. A disabled config yields a no-op confiner
// (logged), so callers always get a usable, non-nil Confiner.
func New(cfg Config, logger *slog.Logger) (Confiner, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if !cfg.Enabled {
		logger.Warn("process confinement disabled by config — execs run unconfined")
		return noopConfiner{}, nil
	}
	return newConfiner(cfg, logger)
}

// noopConfiner does nothing and reports itself unsupported, so the spawn path
// warns rather than refusing.
type noopConfiner struct{}

func (noopConfiner) Prepare(*osexec.Cmd) error { return nil }
func (noopConfiner) Confine(*os.Process) error { return nil }
func (noopConfiner) Supported() bool           { return false }
func (noopConfiner) Close() error              { return nil }

// decide maps confiner support and a per-spawn apply error to an action. On a
// supported platform an apply error is fatal (refuse). On an unsupported
// platform the spawn proceeds but the caller should warn.
func decide(supported bool, applyErr error) (refuse bool, warn bool) {
	if !supported {
		return false, true
	}
	if applyErr != nil {
		return true, false
	}
	return false, false
}
