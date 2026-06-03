//go:build windows

package confine

import (
	"os"
	osexec "os/exec"
	"testing"
	"time"
)

// TestJobKillOnClose proves the job's KILL_ON_JOB_CLOSE tears down a confined
// child when the confiner closes (the deterministic Windows guarantee).
func TestJobKillOnClose(t *testing.T) {
	c, err := New(Config{Enabled: true, MaxMemoryMB: 256, MaxProcesses: 16}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !c.Supported() {
		t.Fatal("expected a supported confiner on windows")
	}

	// A long-lived child: ping loopback ~30s (no extra files needed).
	cmd := osexec.Command("ping", "-n", "30", "127.0.0.1")
	if err := c.Prepare(cmd); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := c.Confine(cmd.Process); err != nil {
		t.Fatalf("Confine: %v", err)
	}
	pid := cmd.Process.Pid

	// Closing the confiner closes the job handle -> KILL_ON_JOB_CLOSE kills the child.
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		if p, _ := os.FindProcess(pid); p != nil {
			// On Windows, signal 0 is unsupported; rely on Wait returning.
		}
		if cmd.ProcessState != nil || waitGone(cmd) {
			return // child reaped/gone
		}
		if time.Now().After(deadline) {
			t.Fatal("confined child survived confiner Close()")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// waitGone reports whether the process has exited (non-blocking best-effort).
func waitGone(cmd *osexec.Cmd) bool {
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(200 * time.Millisecond):
		return false
	}
}
