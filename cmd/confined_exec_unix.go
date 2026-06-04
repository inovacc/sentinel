//go:build linux || darwin

package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/inovacc/sentinel/internal/confine"
	"golang.org/x/sys/unix"
)

// runConfinedExec parses the trampoline args, applies the rlimits to THIS
// process, then replaces the image with the target via syscall.Exec — so the
// limits are in force before the target's first instruction (fail-closed).
func runConfinedExec(args []string) error {
	as, nofile, cpu, rest, err := confine.ParseTrampolineArgs(args)
	if err != nil {
		return err
	}
	if len(rest) == 0 {
		return fmt.Errorf("confined-exec: no target command")
	}

	set := func(res int, v uint64) error {
		if v == 0 {
			return nil // 0 = unlimited; keep the OS default
		}
		return unix.Setrlimit(res, &unix.Rlimit{Cur: v, Max: v})
	}
	if err := set(unix.RLIMIT_AS, as); err != nil {
		return fmt.Errorf("confined-exec: set RLIMIT_AS: %w", err)
	}
	if err := set(unix.RLIMIT_NOFILE, nofile); err != nil {
		return fmt.Errorf("confined-exec: set RLIMIT_NOFILE: %w", err)
	}
	if err := set(unix.RLIMIT_CPU, cpu); err != nil {
		return fmt.Errorf("confined-exec: set RLIMIT_CPU: %w", err)
	}

	path := rest[0]
	if resolved, lerr := exec.LookPath(path); lerr == nil {
		path = resolved
	}
	// Replace this process image with the target. On success this never returns.
	if err := syscall.Exec(path, rest, os.Environ()); err != nil {
		return fmt.Errorf("confined-exec: exec %s: %w", path, err)
	}
	return nil
}
