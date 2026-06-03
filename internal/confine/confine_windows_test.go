//go:build windows

package confine

import (
	osexec "os/exec"
	"strings"
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
	// Closing the confiner closes the job handle -> KILL_ON_JOB_CLOSE kills the child.
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		if cmd.ProcessState != nil || waitGone(cmd) {
			return // child reaped/gone
		}
		if time.Now().After(deadline) {
			t.Fatal("confined child survived confiner Close()")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestRestrictedTokenApplied confirms Prepare sets a restricted primary token on
// the command, so the child runs de-privileged via CreateProcessAsUser.
func TestRestrictedTokenApplied(t *testing.T) {
	c, err := New(Config{Enabled: true, MaxMemoryMB: 256, MaxProcesses: 16}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = c.Close() }()

	cmd := osexec.Command("cmd", "/c", "whoami", "/priv")
	if err := c.Prepare(cmd); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Token == 0 {
		t.Fatal("Prepare must set a restricted token on SysProcAttr")
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		// whoami exits 0 normally; a non-zero exit is acceptable as long as the
		// process ran under the restricted token (the assertion above).
		t.Logf("whoami exit (non-fatal): %v", err)
	}

	// Assert the positive invariant: CreateRestrictedToken with
	// DISABLE_MAX_PRIVILEGE drops every privilege except SeChangeNotifyPrivilege.
	// Checking the exact remaining privilege set (rather than merely the absence
	// of SeDebugPrivilege) keeps the test meaningful even on a non-elevated
	// runner whose base token never carried SeDebugPrivilege to begin with.
	privs := collectPrivileges(string(out))
	if len(privs) != 1 || privs[0] != "SeChangeNotifyPrivilege" {
		t.Errorf("restricted token must expose only SeChangeNotifyPrivilege, got %v\n%s", privs, out)
	}
}

// collectPrivileges extracts the distinct privilege constant names (the leading
// "Se...Privilege" token on each line) from `whoami /priv` output. The output is
// localized but the privilege constants themselves are stable across locales.
func collectPrivileges(out string) []string {
	seen := make(map[string]struct{})
	var privs []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := fields[0]
		if !strings.HasPrefix(name, "Se") || !strings.HasSuffix(name, "Privilege") {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		privs = append(privs, name)
	}
	return privs
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
