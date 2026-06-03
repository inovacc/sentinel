package exec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/inovacc/sentinel/internal/sandbox"
)

func newTestRunner(t *testing.T, allow []string) (*Runner, string) {
	t.Helper()
	root := t.TempDir()
	sb, err := sandbox.New(sandbox.Config{
		Root:            root,
		ExecAllowlist:   allow,
		BlockedCommands: []string{"rm -rf /", "format", "mkfs"},
	})
	if err != nil {
		t.Fatalf("sandbox.New: %v", err)
	}
	return NewRunner(sb), root
}

func TestRun_AllowedCommandCapturesOutput(t *testing.T) {
	r, _ := newTestRunner(t, []string{"go"})
	res, err := r.Run(context.Background(), &RunRequest{Command: "go", Args: []string{"version"}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("exit = %d, want 0 (stderr=%s)", res.ExitCode, res.Stderr)
	}
	if !strings.Contains(res.Stdout, "go version") {
		t.Errorf("stdout = %q, want to contain 'go version'", res.Stdout)
	}
}

func TestRun_NonAllowlistedCommandRefused(t *testing.T) {
	r, _ := newTestRunner(t, []string{"go"})
	_, err := r.Run(context.Background(), &RunRequest{Command: "definitely-not-allowed", Args: []string{"x"}})
	if err == nil {
		t.Fatal("a non-allowlisted command must be refused before execution")
	}
}

func TestRun_BlockedCommandRefused(t *testing.T) {
	r, _ := newTestRunner(t, []string{"rm"})
	_, err := r.Run(context.Background(), &RunRequest{Command: "rm", Args: []string{"-rf", "/"}})
	if err == nil {
		t.Fatal("a blocked command must be refused")
	}
	if !errors.Is(err, sandbox.ErrBlockedCommand) {
		t.Errorf("blocked refusal should wrap sandbox.ErrBlockedCommand, got %v", err)
	}
}

func TestRun_NonZeroExitIsCapturedNotErrored(t *testing.T) {
	r, root := newTestRunner(t, []string{"go"})
	src := "package main\nimport \"os\"\nfunc main() { os.Exit(3) }\n"
	if err := os.WriteFile(filepath.Join(root, "exit3.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := r.Run(context.Background(), &RunRequest{Command: "go", Args: []string{"run", "exit3.go"}})
	// The key property: a command that exits non-zero is reported via ExitCode,
	// not surfaced as a Go error. (`go run` itself exits 1 and prints the child's
	// "exit status 3" to stderr, so we assert non-zero rather than an exact code.)
	if err != nil {
		t.Fatalf("a non-zero exit should be captured, not returned as an error: %v", err)
	}
	if res.ExitCode == 0 {
		t.Errorf("exit = 0, want non-zero for a failing command (stderr=%s)", res.Stderr)
	}
}

func TestRun_WorkingDirTraversalRejected(t *testing.T) {
	r, _ := newTestRunner(t, []string{"go"})
	_, err := r.Run(context.Background(), &RunRequest{
		Command: "go", Args: []string{"version"}, WorkingDir: "../../etc",
	})
	if err == nil {
		t.Fatal("a working dir escaping the sandbox must be rejected")
	}
}

func TestRunBackground_AllowedReturnsPID(t *testing.T) {
	r, _ := newTestRunner(t, []string{"go"})
	res, err := r.Run(context.Background(), &RunRequest{Command: "go", Args: []string{"version"}, Background: true})
	if err != nil {
		t.Fatalf("background Run: %v", err)
	}
	if !strings.Contains(res.Stdout, "background") {
		t.Errorf("stdout = %q, want a background PID message", res.Stdout)
	}
}

func TestRunBackground_NonAllowlistedRefused(t *testing.T) {
	r, _ := newTestRunner(t, []string{"go"})
	_, err := r.Run(context.Background(), &RunRequest{Command: "nope", Background: true})
	if err == nil {
		t.Fatal("a background non-allowlisted command must be refused")
	}
}

func TestRunStream_AllowedStreamsOutput(t *testing.T) {
	r, _ := newTestRunner(t, []string{"go"})
	var mu sync.Mutex
	var got strings.Builder
	res, err := r.RunStream(context.Background(), &RunRequest{Command: "go", Args: []string{"version"}},
		func(stream string, data []byte) {
			mu.Lock()
			defer mu.Unlock()
			got.Write(data)
		})
	if err != nil {
		t.Fatalf("RunStream: %v", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("exit = %d, want 0", res.ExitCode)
	}
	if !strings.Contains(got.String(), "go version") {
		t.Errorf("streamed output = %q, want to contain 'go version'", got.String())
	}
}

func TestRunStream_NonAllowlistedRefused(t *testing.T) {
	r, _ := newTestRunner(t, []string{"go"})
	_, err := r.RunStream(context.Background(), &RunRequest{Command: "nope"}, func(string, []byte) {})
	if err == nil {
		t.Fatal("a streamed non-allowlisted command must be refused")
	}
}
