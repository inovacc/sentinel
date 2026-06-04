//go:build linux || darwin

package confine

import (
	"fmt"
	"log/slog"
	"os"
	osexec "os/exec"
)

// unixConfiner applies Unix rlimits to spawned children via a re-exec
// trampoline: Prepare rewrites cmd to invoke `sentinel __confined-exec`, which
// sets RLIMIT_AS/NOFILE/CPU on itself and then exec's the real target — so the
// limits are in force before the target's first instruction (fail-closed). The
// daemon's own rlimits are never touched. There is no post-start handle to
// manage, so Confine is a no-op.
type unixConfiner struct {
	cfg    Config
	logger *slog.Logger
	self   string // path to the running daemon binary (the trampoline host)
}

func newConfiner(cfg Config, logger *slog.Logger) (Confiner, error) {
	if logger == nil {
		logger = slog.Default()
	}
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("confine: locate self for trampoline: %w", err)
	}
	return &unixConfiner{cfg: cfg, logger: logger, self: self}, nil
}

func (c *unixConfiner) Supported() bool { return true }

// Prepare rewrites cmd so it runs through the rlimit trampoline. It preserves
// the original Dir and Env; only the executable + argv are rewritten.
func (c *unixConfiner) Prepare(cmd *osexec.Cmd) error {
	target := cmd.Path
	if target == "" && len(cmd.Args) > 0 {
		target = cmd.Args[0]
	}
	origArgs := cmd.Args
	if len(origArgs) == 0 {
		origArgs = []string{target}
	}

	prefix := trampolinePrefix(c.cfg) // [subcommand --as .. --nofile .. --cpu .. --]
	newArgs := make([]string, 0, 1+len(prefix)+len(origArgs))
	newArgs = append(newArgs, c.self) // argv[0]
	newArgs = append(newArgs, prefix...)
	newArgs = append(newArgs, origArgs...) // original target + its args

	cmd.Path = c.self
	cmd.Args = newArgs
	return nil
}

// Confine is a no-op: the trampoline applies limits in-process before exec, so
// there is nothing to attach after Start.
func (c *unixConfiner) Confine(*os.Process) error { return nil }

func (c *unixConfiner) Close() error { return nil }
