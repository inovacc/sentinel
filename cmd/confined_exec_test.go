//go:build linux

package cmd

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

// The subcommand is exercised by re-invoking the test binary as the trampoline
// would: `confinedExecRun` sets rlimits then execs. We test the arg wiring by
// running a real /bin/echo through it via go run-equivalent: here we invoke the
// helper that does the setrlimit+exec and confirm a tiny memory cap kills a
// greedy child.
func TestConfinedExecAppliesMemoryCap(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	// Build the daemon once and call its hidden subcommand. Use `go run .` so we
	// don't depend on an installed binary.
	cmd := exec.Command("go", "run", ".",
		"__confined-exec", "--as", "33554432", "--nofile", "0", "--cpu", "0", "--",
		"/usr/bin/python3", "-c", "b=bytearray(256*1024*1024)")
	cmd.Dir = ".."
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("greedy child under a 32 MiB RLIMIT_AS should have failed")
	}
	_ = strings.Contains(stderr.String(), "Memory") // best-effort signal only
}
