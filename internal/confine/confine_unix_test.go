//go:build linux

package confine

import (
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

func TestUnixConfinerRewritesCmdToTrampoline(t *testing.T) {
	c, err := newConfiner(Config{
		Enabled:            true,
		ProcMaxMemoryBytes: 64 << 20,
		ProcMaxOpenFiles:   256,
	}, nil)
	if err != nil {
		t.Fatalf("newConfiner: %v", err)
	}
	if !c.Supported() {
		t.Fatal("unix confiner should report Supported() == true")
	}
	cmd := exec.Command("/bin/echo", "hello")
	if err := c.Prepare(cmd); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	// After Prepare, cmd must invoke the trampoline: argv[0] is the daemon binary
	// (os.Executable), argv[1] is the hidden subcommand.
	self, _ := os.Executable()
	if cmd.Path != self {
		t.Fatalf("cmd.Path = %q, want daemon binary %q", cmd.Path, self)
	}
	if len(cmd.Args) < 2 || cmd.Args[1] != TrampolineSubcommand {
		t.Fatalf("cmd.Args = %v, want trampoline subcommand at [1]", cmd.Args)
	}
}

func TestDaemonOwnRlimitsUnchangedByConfiner(t *testing.T) {
	var before unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_AS, &before); err != nil {
		t.Skipf("getrlimit unsupported: %v", err)
	}
	c, _ := newConfiner(Config{Enabled: true, ProcMaxMemoryBytes: 64 << 20}, nil)
	cmd := exec.Command("/bin/echo")
	_ = c.Prepare(cmd)
	var after unix.Rlimit
	_ = unix.Getrlimit(unix.RLIMIT_AS, &after)
	if before.Cur != after.Cur {
		t.Fatalf("daemon RLIMIT_AS changed: %d -> %d (must confine child only)", before.Cur, after.Cur)
	}
}
