//go:build !windows

package exec

import (
	"os"
	"syscall"
)

// rlimitSignalKill reports whether the child's exit is a signal consistent with
// an OS resource-limit kill. SIGKILL covers RLIMIT_AS / cgroup-OOM kills (the
// kernel sends an uncatchable SIGKILL when address space is exhausted) and
// SIGXCPU covers RLIMIT_CPU (soft CPU-time limit). This is a heuristic: SIGKILL
// in particular can also come from an operator kill or the context-timeout kill,
// so callers only invoke this for a CONFINED child where an rlimit was set.
func rlimitSignalKill(ps *os.ProcessState) bool {
	if ps == nil {
		return false
	}
	ws, ok := ps.Sys().(syscall.WaitStatus)
	if !ok {
		return false
	}
	if !ws.Signaled() {
		return false
	}
	switch ws.Signal() {
	case syscall.SIGKILL, syscall.SIGXCPU:
		return true
	default:
		return false
	}
}
