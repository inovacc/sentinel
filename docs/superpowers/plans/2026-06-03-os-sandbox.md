# OS Sandbox (Process Confinement) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Confine every process Sentinel spawns on Windows with a Job Object (memory / active-process / CPU caps + kill-on-job-close) and a restricted token (privilege drop), fail-closed on Windows and no-op-with-warning elsewhere.

**Architecture:** A new `internal/confine` package exposes a small `Confiner` interface with platform-split implementations. The `exec.Runner` and `worker.Pool` each take a `Confiner` and call `Prepare` (before `Start`) and `Confine` (after `Start`) around process creation, applying a fail-closed-on-Windows posture. Config lives in `settings.Confine`.

**Tech Stack:** Go 1.26, `golang.org/x/sys/windows` (Job Object + token APIs; `CreateRestrictedToken` bound via `advapi32` LazyDLL), `os/exec` (`SysProcAttr.Token` → `CreateProcessAsUser`).

Spec: `docs/superpowers/specs/2026-06-03-os-sandbox-design.md`.

---

## File Structure

- Create `internal/confine/confine.go` — `Confiner` interface, `Config`, `New` dispatcher, `noopConfiner`, `decide` posture helper. (cross-platform)
- Create `internal/confine/confine_other.go` (`//go:build !windows`) — `newConfiner` returns the no-op.
- Create `internal/confine/confine_windows.go` (`//go:build windows`) — Job Object + restricted token confiner.
- Create `internal/confine/confine_test.go` — cross-platform unit tests (`decide`, no-op `Supported()`).
- Create `internal/confine/confine_windows_test.go` (`//go:build windows`) — Windows integration tests.
- Modify `internal/settings/settings.go` — add `Confine` config block + defaults + validation; bump schema version + migration.
- Modify `internal/exec/exec.go` — `Runner` gains a `Confiner`; `Prepare`/`Confine` + posture around `Start`.
- Modify `internal/worker/pool.go` — `Pool` gains a `WithConfiner` option; same integration in `Spawn`.
- Modify `cmd/serve.go` — build the confiner from config, inject into `Runner`/`Pool`, `Close` on shutdown.

---

## Task 1: Confiner interface, no-op confiner, posture helper

**Files:**
- Create: `internal/confine/confine.go`
- Create: `internal/confine/confine_other.go`
- Test: `internal/confine/confine_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/confine/confine_test.go
package confine

import "testing"

func TestDecide(t *testing.T) {
	tests := []struct {
		name              string
		supported         bool
		applyErr          error
		wantRefuse, wantWarn bool
	}{
		{"supported, applied", true, nil, false, false},
		{"supported, apply error -> refuse", true, errTest, true, false},
		{"unsupported, no error -> warn", false, nil, false, true},
		{"unsupported, error -> warn (never refuse)", false, errTest, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			refuse, warn := decide(tt.supported, tt.applyErr)
			if refuse != tt.wantRefuse || warn != tt.wantWarn {
				t.Fatalf("decide(%v,%v) = (%v,%v), want (%v,%v)",
					tt.supported, tt.applyErr, refuse, warn, tt.wantRefuse, tt.wantWarn)
			}
		})
	}
}

func TestNoopConfinerUnsupported(t *testing.T) {
	c, err := New(Config{Enabled: true}, nil) // on non-windows this is the no-op
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = c.Close() }()
	if c.Supported() {
		t.Skip("real confiner on this platform; covered by the windows test")
	}
	if err := c.Prepare(nil); err != nil {
		t.Errorf("noop Prepare should not error: %v", err)
	}
	if err := c.Confine(nil); err != nil {
		t.Errorf("noop Confine should not error: %v", err)
	}
}

func TestDisabledConfigYieldsNoop(t *testing.T) {
	c, err := New(Config{Enabled: false}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = c.Close() }()
	if c.Supported() {
		t.Error("a disabled confiner must report Supported()==false")
	}
}

var errTest = &testErr{}

type testErr struct{}

func (*testErr) Error() string { return "test error" }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/confine/ -run 'TestDecide|TestNoop|TestDisabled' -v`
Expected: FAIL — build error, `undefined: New`, `undefined: decide`, `undefined: Config`.

- [ ] **Step 3: Write the cross-platform package file**

```go
// internal/confine/confine.go

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
```

```go
// internal/confine/confine_other.go
//go:build !windows

package confine

import "log/slog"

func newConfiner(_ Config, _ *slog.Logger) (Confiner, error) {
	return noopConfiner{}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/confine/ -run 'TestDecide|TestNoop|TestDisabled' -v`
Expected: PASS (on non-Windows, `TestNoopConfinerUnsupported` exercises the no-op; `TestDecide` and `TestDisabled` pass everywhere).

- [ ] **Step 5: Commit**

```bash
git add internal/confine/confine.go internal/confine/confine_other.go internal/confine/confine_test.go
git commit -m "feat(confine): Confiner interface, no-op confiner, fail-closed posture"
```

---

## Task 2: Confine settings block (config + defaults + validation + migration)

**Files:**
- Modify: `internal/settings/settings.go`
- Test: `internal/settings/settings_test.go` (add cases)

> First read `internal/settings/settings.go` to match the existing `Config` struct, `DefaultConfig`, `Validate`, `CurrentConfigVersion`, and `Migrate` patterns. The snippets below assume a top-level `Config` with sub-structs and a `CurrentConfigVersion` constant; adapt field placement to the real file.

- [ ] **Step 1: Write the failing test**

```go
// internal/settings/settings_test.go (add)
func TestDefaultConfigHasConfineDefaults(t *testing.T) {
	c := DefaultConfig()
	if !c.Confine.Enabled {
		t.Error("confine should default to enabled")
	}
	if c.Confine.MaxMemoryMB == 0 || c.Confine.MaxProcesses == 0 {
		t.Errorf("confine defaults look unset: %+v", c.Confine)
	}
}

func TestConfineValidateRejectsBadCPU(t *testing.T) {
	c := DefaultConfig()
	c.Confine.CPUPercent = 250 // > 100
	if err := c.Validate(); err == nil {
		t.Error("CPUPercent > 100 should be rejected by Validate")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/settings/ -run 'Confine' -v`
Expected: FAIL — `c.Confine undefined`.

- [ ] **Step 3: Add the Confine config**

Add the struct + defaults + validation, and bump the schema version so existing configs migrate. In `internal/settings/settings.go`:

```go
// ConfineConfig controls OS-level process confinement (Windows v1).
type ConfineConfig struct {
	Enabled      bool   `yaml:"enabled"`
	MaxMemoryMB  uint64 `yaml:"max_memory_mb"`
	CPUPercent   uint32 `yaml:"cpu_percent"`
	MaxProcesses uint32 `yaml:"max_processes"`
}
```

Add `Confine ConfineConfig \`yaml:"confine"\`` to the top-level `Config` struct. In `DefaultConfig()` set:

```go
cfg.Confine = ConfineConfig{Enabled: true, MaxMemoryMB: 1024, CPUPercent: 80, MaxProcesses: 64}
```

In `Validate()` add:

```go
if c.Confine.CPUPercent > 100 {
	return fmt.Errorf("confine.cpu_percent must be 0..100, got %d", c.Confine.CPUPercent)
}
```

In `Migrate()` (the version-upgrade path), default any zero Confine block on configs written before this version:

```go
if c.Confine == (ConfineConfig{}) {
	c.Confine = ConfineConfig{Enabled: true, MaxMemoryMB: 1024, CPUPercent: 80, MaxProcesses: 64}
}
```

Increment `CurrentConfigVersion` by 1 (so older on-disk configs are migrated by `sentinel doctor --fix` / load).

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/settings/ -run 'Confine' -v`
Expected: PASS. Then `go test ./internal/settings/` — all settings tests still pass (the version bump + migration keep older configs valid).

- [ ] **Step 5: Commit**

```bash
git add internal/settings/settings.go internal/settings/settings_test.go
git commit -m "feat(settings): add confine config block with migration"
```

---

## Task 3: Windows Job Object (memory / active-process / kill-on-close)

**Files:**
- Create: `internal/confine/confine_windows.go`
- Test: `internal/confine/confine_windows_test.go`

> This task and Tasks 4–5 only build/run on Windows. On the CI matrix, run them on the Windows runner. Locally, build with `GOOS=windows go build ./internal/confine/` to typecheck.

- [ ] **Step 1: Write the failing test (Windows-tagged)**

```go
// internal/confine/confine_windows_test.go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run (on Windows): `go test ./internal/confine/ -run TestJobKillOnClose -v`
Expected: FAIL — `undefined: newConfiner` for windows build (no `confine_windows.go` yet).

- [ ] **Step 3: Implement the Windows confiner skeleton + Job Object**

```go
// internal/confine/confine_windows.go
//go:build windows

package confine

import (
	"fmt"
	"log/slog"
	"os"
	osexec "os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsConfiner struct {
	cfg    Config
	logger *slog.Logger
	token  windows.Token  // restricted primary token (Task 4); 0 until then
	job    windows.Handle // job object
}

func newConfiner(cfg Config, logger *slog.Logger) (Confiner, error) {
	job, err := newJobObject(cfg)
	if err != nil {
		return nil, fmt.Errorf("confine: job object: %w", err)
	}
	return &windowsConfiner{cfg: cfg, logger: logger, job: job}, nil
}

func (c *windowsConfiner) Supported() bool { return true }

func (c *windowsConfiner) Prepare(cmd *osexec.Cmd) error {
	// Token is wired in Task 4; nothing required here yet.
	_ = cmd
	return nil
}

func (c *windowsConfiner) Confine(p *os.Process) error {
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(p.Pid))
	if err != nil {
		return fmt.Errorf("confine: open process: %w", err)
	}
	defer func() { _ = windows.CloseHandle(h) }()
	if err := windows.AssignProcessToJobObject(c.job, h); err != nil {
		return fmt.Errorf("confine: assign to job: %w", err)
	}
	return nil
}

func (c *windowsConfiner) Close() error {
	_ = windows.CloseHandle(c.job) // KILL_ON_JOB_CLOSE terminates remaining children
	if c.token != 0 {
		_ = c.token.Close()
	}
	return nil
}

func newJobObject(cfg Config) (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}

	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if cfg.MaxProcesses > 0 {
		info.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
		info.BasicLimitInformation.ActiveProcessLimit = cfg.MaxProcesses
	}
	if cfg.MaxMemoryMB > 0 {
		info.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY
		info.ProcessMemoryLimit = uintptr(cfg.MaxMemoryMB) * 1024 * 1024
	}
	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		_ = windows.CloseHandle(job)
		return 0, err
	}

	if cfg.CPUPercent > 0 && cfg.CPUPercent < 100 {
		if err := setCPURate(job, cfg.CPUPercent); err != nil {
			_ = windows.CloseHandle(job)
			return 0, err
		}
	}
	return job, nil
}

// jobObjectCPURateControlInformation mirrors the Win32 struct (not wrapped in
// x/sys/windows v0.45). ControlFlags ENABLE(0x1)|HARD_CAP(0x4); Value is the cap
// in 1/100 of one percent (e.g. 80% -> 8000).
type jobObjectCPURateControlInformation struct {
	ControlFlags uint32
	Value        uint32
}

const (
	cpuRateControlEnable  = 0x1
	cpuRateControlHardCap = 0x4
)

func setCPURate(job windows.Handle, pct uint32) error {
	info := jobObjectCPURateControlInformation{
		ControlFlags: cpuRateControlEnable | cpuRateControlHardCap,
		Value:        pct * 100,
	}
	_, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectCpuRateControlInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	)
	return err
}
```

- [ ] **Step 4: Run test to verify it passes (Windows)**

Run (on Windows): `go test ./internal/confine/ -run TestJobKillOnClose -v`
Expected: PASS — the confined `ping` child is killed when `Close()` closes the job handle.

- [ ] **Step 5: Commit**

```bash
git add internal/confine/confine_windows.go internal/confine/confine_windows_test.go
git commit -m "feat(confine): windows Job Object (memory/process caps + kill-on-close)"
```

---

## Task 4: Windows restricted token (privilege drop)

**Files:**
- Modify: `internal/confine/confine_windows.go`
- Test: `internal/confine/confine_windows_test.go` (add)

- [ ] **Step 1: Write the failing test (Windows)**

```go
// internal/confine/confine_windows_test.go (add)

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
	// SeDebugPrivilege must NOT be present under the restricted token.
	if strings.Contains(string(out), "SeDebugPrivilege") {
		t.Errorf("restricted token still exposes SeDebugPrivilege:\n%s", out)
	}
}
```

Add `"strings"` to the test file imports.

- [ ] **Step 2: Run test to verify it fails (Windows)**

Run (on Windows): `go test ./internal/confine/ -run TestRestrictedTokenApplied -v`
Expected: FAIL — `cmd.SysProcAttr.Token == 0` (Prepare doesn't set a token yet).

- [ ] **Step 3: Build the restricted token and set it in Prepare**

Add to `internal/confine/confine_windows.go`:

```go
var (
	modadvapi32               = windows.NewLazySystemDLL("advapi32.dll")
	procCreateRestrictedToken = modadvapi32.NewProc("CreateRestrictedToken")
)

// DISABLE_MAX_PRIVILEGE drops all privileges except SeChangeNotifyPrivilege.
const disableMaxPrivilege = 0x1

// newRestrictedToken duplicates the current process token, disables the
// Administrators group SID, and drops privileges, returning a primary token
// suitable for CreateProcessAsUser.
func newRestrictedToken() (windows.Token, error) {
	var base windows.Token
	if err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_QUERY,
		&base,
	); err != nil {
		return 0, fmt.Errorf("open process token: %w", err)
	}
	defer base.Close()

	adminSid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return 0, fmt.Errorf("admin sid: %w", err)
	}
	disable := []windows.SIDAndAttributes{{Sid: adminSid, Attributes: 0}}

	var restricted windows.Token
	r1, _, e1 := procCreateRestrictedToken.Call(
		uintptr(base),
		uintptr(disableMaxPrivilege),
		uintptr(len(disable)),
		uintptr(unsafe.Pointer(&disable[0])),
		0, 0, // PrivilegesToDelete (covered by DISABLE_MAX_PRIVILEGE)
		0, 0, // SidsToRestrict
		uintptr(unsafe.Pointer(&restricted)),
	)
	if r1 == 0 {
		return 0, fmt.Errorf("CreateRestrictedToken: %w", e1)
	}
	return restricted, nil
}
```

Wire it into `newConfiner` and `Prepare`:

```go
func newConfiner(cfg Config, logger *slog.Logger) (Confiner, error) {
	tok, err := newRestrictedToken()
	if err != nil {
		return nil, fmt.Errorf("confine: restricted token: %w", err)
	}
	job, err := newJobObject(cfg)
	if err != nil {
		_ = tok.Close()
		return nil, fmt.Errorf("confine: job object: %w", err)
	}
	return &windowsConfiner{cfg: cfg, logger: logger, token: tok, job: job}, nil
}

func (c *windowsConfiner) Prepare(cmd *osexec.Cmd) error {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Token = syscall.Token(c.token)
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes (Windows)**

Run (on Windows): `go test ./internal/confine/ -run 'TestRestrictedTokenApplied|TestJobKillOnClose' -v`
Expected: PASS — token is set; `SeDebugPrivilege` absent.

- [ ] **Step 5: Commit**

```bash
git add internal/confine/confine_windows.go internal/confine/confine_windows_test.go
git commit -m "feat(confine): windows restricted token (drop admin SID + privileges)"
```

---

## Task 5: Cross-platform test fake for integration

**Files:**
- Create: `internal/confine/fake.go`
- Test: covered by Tasks 6–7

> A fake Confiner lets the `exec`/`worker` integration logic be tested on every platform (including Linux CI) without Windows. Ship it in the package (not `_test.go`) so other packages can import it in their tests.

- [ ] **Step 1: Implement the fake**

```go
// internal/confine/fake.go

package confine

import (
	"os"
	osexec "os/exec"
)

// Fake is a test Confiner whose behavior is fully controllable. It records calls
// so consumers can assert the spawn path invokes Prepare/Confine.
type Fake struct {
	SupportedVal bool
	PrepareErr   error
	ConfineErr   error
	Prepared     int
	Confined     int
}

func (f *Fake) Prepare(*osexec.Cmd) error { f.Prepared++; return f.PrepareErr }
func (f *Fake) Confine(*os.Process) error { f.Confined++; return f.ConfineErr }
func (f *Fake) Supported() bool           { return f.SupportedVal }
func (f *Fake) Close() error              { return nil }
```

- [ ] **Step 2: Build to verify it compiles**

Run: `go build ./internal/confine/`
Expected: success.

- [ ] **Step 3: Commit**

```bash
git add internal/confine/fake.go
git commit -m "test(confine): injectable Fake confiner for integration tests"
```

---

## Task 6: Integrate the confiner into `exec.Runner`

**Files:**
- Modify: `internal/exec/exec.go`
- Test: `internal/exec/exec_confine_test.go`

> Read the current `Runner`, `NewRunner`, `Run`, `runBackground`, `RunStream`, and `buildCmd`. The `Runner` gains a `confiner confine.Confiner` field. `buildCmd` calls `Prepare`; each path calls `Confine` after `Start`/`Run` and applies the posture. Use `decideRefusal` (a tiny exported-for-test helper or reuse the package's `decide` via a thin wrapper in `exec`).

- [ ] **Step 1: Write the failing test**

```go
// internal/exec/exec_confine_test.go
package exec

import (
	"context"
	"testing"

	"github.com/inovacc/sentinel/internal/confine"
)

func newConfinedRunner(t *testing.T, allow []string, c confine.Confiner) *Runner {
	t.Helper()
	r, _ := newTestRunner(t, allow) // from exec_test.go
	r.confiner = c
	return r
}

func TestRun_CallsConfiner(t *testing.T) {
	f := &confine.Fake{SupportedVal: true}
	r := newConfinedRunner(t, []string{"go"}, f)
	if _, err := r.Run(context.Background(), &RunRequest{Command: "go", Args: []string{"version"}}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if f.Prepared == 0 || f.Confined == 0 {
		t.Errorf("Run must Prepare and Confine (prepared=%d confined=%d)", f.Prepared, f.Confined)
	}
}

func TestRun_FailClosedWhenSupportedConfineErrors(t *testing.T) {
	f := &confine.Fake{SupportedVal: true, ConfineErr: errConfine}
	r := newConfinedRunner(t, []string{"go"}, f)
	if _, err := r.Run(context.Background(), &RunRequest{Command: "go", Args: []string{"version"}}); err == nil {
		t.Fatal("a supported confiner that fails to confine must fail the exec closed")
	}
}

func TestRun_WarnsButProceedsWhenUnsupported(t *testing.T) {
	f := &confine.Fake{SupportedVal: false}
	r := newConfinedRunner(t, []string{"go"}, f)
	if _, err := r.Run(context.Background(), &RunRequest{Command: "go", Args: []string{"version"}}); err != nil {
		t.Fatalf("unsupported confiner must not block exec: %v", err)
	}
}

var errConfine = &confineErr{}

type confineErr struct{}

func (*confineErr) Error() string { return "confine failed" }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/exec/ -run 'CallsConfiner|FailClosed|WarnsButProceeds' -v`
Expected: FAIL — `r.confiner undefined`.

- [ ] **Step 3: Add the confiner to Runner and apply it**

In `internal/exec/exec.go`, add the field and a default, expose `decide`, and wire the two-phase call. Export `decide` from confine by adding a thin helper, or replicate the rule locally:

```go
// in confine: add exported wrapper so exec can reuse the rule.
// internal/confine/confine.go (add)
func Decide(supported bool, applyErr error) (refuse bool, warn bool) {
	return decide(supported, applyErr)
}
```

```go
// internal/exec/exec.go (changes)

import (
	// ...existing...
	"github.com/inovacc/sentinel/internal/confine"
)

type Runner struct {
	sandbox  *sandbox.Sandbox
	confiner confine.Confiner
	logger   *slog.Logger
}

func NewRunner(sb *sandbox.Sandbox) *Runner {
	return &Runner{sandbox: sb, confiner: confine.Confiner(nil)}
}

// NewRunnerWithConfiner injects a confiner and logger (used by the daemon).
func NewRunnerWithConfiner(sb *sandbox.Sandbox, c confine.Confiner, logger *slog.Logger) *Runner {
	if logger == nil {
		logger = slog.Default()
	}
	return &Runner{sandbox: sb, confiner: c, logger: logger}
}

// confine applies the confiner to a started process, returning an error when the
// platform supports confinement but it could not be applied (fail-closed).
func (r *Runner) applyConfine(p *os.Process) error {
	if r.confiner == nil {
		return nil // no confiner configured (e.g. legacy callers/tests)
	}
	err := r.confiner.Confine(p)
	refuse, warn := confine.Decide(r.confiner.Supported(), err)
	if warn && r.logger != nil {
		r.logger.Warn("exec: process is running unconfined (no OS sandbox on this platform)")
	}
	if refuse {
		_ = p.Kill()
		return fmt.Errorf("exec: refusing unconfined process: %w", err)
	}
	return nil
}
```

In `buildCmd`, after building `cmd` and before returning it, call `Prepare`:

```go
	if r.confiner != nil {
		if err := r.confiner.Prepare(cmd); err != nil {
			return nil, fmt.Errorf("exec: prepare confinement: %w", err)
		}
	}
	return cmd, nil
```

In `Run` (non-background), after `cmd.Start()`... note `Run` uses `cmd.Run()` which blocks. Change `Run` to `cmd.Start()` then `applyConfine(cmd.Process)` then `cmd.Wait()`:

```go
	start := time.Now()
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("exec: start command: %w", err)
	}
	if err := r.applyConfine(cmd.Process); err != nil {
		return nil, err
	}
	runErr := cmd.Wait()
	duration := time.Since(start).Milliseconds()
	// ...existing result handling unchanged...
```

In `runBackground` and `RunStream`, add `r.applyConfine(cmd.Process)` immediately after their `cmd.Start()` (before `Release()` in background; before the stream goroutines in `RunStream`), returning its error.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/exec/ -v`
Expected: PASS — including the existing `exec_test.go` suite (a nil confiner is a no-op, preserving current behavior) and the three new confiner tests.

- [ ] **Step 5: Commit**

```bash
git add internal/exec/exec.go internal/exec/exec_confine_test.go internal/confine/confine.go
git commit -m "feat(exec): apply process confiner with fail-closed posture"
```

---

## Task 7: Integrate the confiner into `worker.Pool`

**Files:**
- Modify: `internal/worker/pool.go`
- Test: `internal/worker/pool_confine_test.go`

> Mirror Task 6 in `Pool.Spawn`: add a `confiner confine.Confiner` field set by a `WithConfiner` option, call `Prepare` on the built `cmd`, call `Confine` after `cmd.Start()`, apply posture (fail-closed kills the just-started process and returns an error).

- [ ] **Step 1: Write the failing test**

```go
// internal/worker/pool_confine_test.go
package worker

import (
	"context"
	"testing"

	"github.com/inovacc/sentinel/internal/confine"
)

func TestSpawn_CallsConfiner(t *testing.T) {
	f := &confine.Fake{SupportedVal: true}
	p, _, _ := newTestPool(t, []string{"go"}, WithConfiner(f))
	if _, err := p.Spawn(context.Background(), "go", []string{"version"}, "", nil, "", nil, 0); err != nil {
		t.Fatalf("Spawn: %v", err)
	}
	if f.Prepared == 0 || f.Confined == 0 {
		t.Errorf("Spawn must Prepare and Confine (prepared=%d confined=%d)", f.Prepared, f.Confined)
	}
}

func TestSpawn_FailClosedOnConfineError(t *testing.T) {
	f := &confine.Fake{SupportedVal: true, ConfineErr: errConfineWorker}
	p, _, _ := newTestPool(t, []string{"go"}, WithConfiner(f))
	if _, err := p.Spawn(context.Background(), "go", []string{"version"}, "", nil, "", nil, 0); err == nil {
		t.Fatal("a supported confiner that fails must fail the spawn closed")
	}
}

var errConfineWorker = &confineErrW{}

type confineErrW struct{}

func (*confineErrW) Error() string { return "confine failed" }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/worker/ -run 'CallsConfiner|FailClosed' -v`
Expected: FAIL — `WithConfiner undefined`.

- [ ] **Step 3: Add WithConfiner + wire into Spawn**

In `internal/worker/pool.go`:

```go
import "github.com/inovacc/sentinel/internal/confine"

// add to Pool struct:
//   confiner confine.Confiner

// WithConfiner sets the OS process confiner.
func WithConfiner(c confine.Confiner) Option { return func(p *Pool) { p.confiner = c } }
```

In `Spawn`, after building `cmd` and before `cmd.Start()`:

```go
	if p.confiner != nil {
		if err := p.confiner.Prepare(cmd); err != nil {
			return nil, fmt.Errorf("worker: prepare confinement: %w", err)
		}
	}
```

After `cmd.Start()` succeeds:

```go
	if p.confiner != nil {
		cErr := p.confiner.Confine(cmd.Process)
		refuse, warn := confine.Decide(p.confiner.Supported(), cErr)
		if warn {
			p.logger.Warn("worker: process running unconfined (no OS sandbox on this platform)")
		}
		if refuse {
			_ = cmd.Process.Kill()
			return nil, fmt.Errorf("worker: refusing unconfined process: %w", cErr)
		}
	}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/worker/ -v`
Expected: PASS — existing pool tests (nil confiner = no-op) plus the two new ones.

- [ ] **Step 5: Commit**

```bash
git add internal/worker/pool.go internal/worker/pool_confine_test.go
git commit -m "feat(worker): apply process confiner with fail-closed posture"
```

---

## Task 8: Wire the confiner into the daemon

**Files:**
- Modify: `cmd/serve.go`
- Test: `cmd/serve_test.go` (the existing boot smoke test guards this)

> Build one confiner from config in `buildDaemon`, inject it into the `Runner` (via `registerServices`) and the `Pool` (via `WithConfiner`), and `Close()` it on shutdown. Read `registerServices` and the pool construction site first.

- [ ] **Step 1: Build the confiner in buildDaemon**

In `cmd/serve.go`, where the worker pool and services are constructed:

```go
import "github.com/inovacc/sentinel/internal/confine"

// after cfg is loaded and logger built:
confiner, err := confine.New(confine.Config{
	Enabled:      cfg.Confine.Enabled,
	MaxMemoryMB:  cfg.Confine.MaxMemoryMB,
	CPUPercent:   cfg.Confine.CPUPercent,
	MaxProcesses: cfg.Confine.MaxProcesses,
}, logger)
if err != nil {
	return d, fmt.Errorf("init confiner: %w", err)
}
d.addCleanup(func() { _ = confiner.Close() })
```

Pass `confiner` into the worker pool:

```go
pool, err := worker.NewPool(db, sb, worker.WithLogger(logger), worker.WithConfiner(confiner))
```

And into `registerServices` so the exec service's runner is confined:

```go
func registerServices(grpcServer *sentinelgrpc.Server, sb *sandbox.Sandbox, sessionMgr *session.Manager, pool *worker.Pool, confiner confine.Confiner, logger *slog.Logger) {
	runner := exec.NewRunnerWithConfiner(sb, confiner, logger)
	// ...rest unchanged...
}
```

Update the `registerServices` call site to pass `confiner`.

- [ ] **Step 2: Build + run the boot smoke test**

Run: `go build ./... && go test ./cmd/ -run 'TestBuildDaemon|TestRunDaemonCtxBootAndShutdown' -v`
Expected: PASS — the daemon builds the confiner (a real one on Windows, no-op elsewhere), boots, and shuts down cleanly, closing the confiner.

- [ ] **Step 3: Commit**

```bash
git add cmd/serve.go
git commit -m "feat(serve): wire process confiner into exec runner and worker pool"
```

---

## Task 9: Threat-model + status update

**Files:**
- Modify: `docs/security/THREAT-MODEL.md`
- Modify: `docs/superpowers/HARDENING-STATUS.md`

- [ ] **Step 1: Update the threat model**

Mark **T5.1** `🟡` — "OS confinement on Windows (Job Object + restricted token) via `internal/confine`; fail-closed on Windows, no-op+warn on Linux/macOS pending v2 (Landlock/seccomp)." Point Code → `internal/confine/`, Test → `internal/confine/confine_windows_test.go`. Note **T5.3** partially covered (process/memory/CPU caps).

- [ ] **Step 2: Update HARDENING-STATUS.md**

Add a short entry: Phase 3.6 v1 shipped (Windows process confinement); v2 (Linux native) and v3 (AppContainer / container-per-exec) remain.

- [ ] **Step 3: Full verification**

Run:
```bash
go build ./...
go test ./...
go vet ./...
GOOS=windows go build ./internal/confine/   # typecheck the windows files from any host
```
Expected: all pass; the Windows build compiles the windows-tagged files.

- [ ] **Step 4: Commit**

```bash
git add docs/security/THREAT-MODEL.md docs/superpowers/HARDENING-STATUS.md
git commit -m "docs(security): record Phase 3.6 v1 (windows process confinement)"
```

---

## Self-Review

- **Spec coverage:** Confiner interface (T1) ✓; no-op + fail-closed posture (T1) ✓; Windows Job Object memory/process/CPU + kill-on-close (T3) ✓; restricted token privilege drop (T4) ✓; config block + migration (T2) ✓; exec integration (T6) ✓; worker integration (T7) ✓; daemon wiring (T8) ✓; testing strategy — cross-platform via Fake (T5–T7) + Windows integration (T3–T4) ✓; phasing/threat-model (T9) ✓. The spec's "assign-after-Start race" and "shared vs per-exec job" appear as the documented v1 limitation (shared job, kill-on-daemon-exit) — consistent.
- **Placeholder scan:** No TBD/TODO. Tasks 2/6/7/8 say "read the existing file first" because they modify code whose exact surrounding lines must match the live file; the inserted code is fully specified.
- **Type consistency:** `Confiner` (Prepare/Confine/Supported/Close), `confine.Decide`, `confine.Fake`, `confine.Config`, `NewRunnerWithConfiner`, `WithConfiner` are used identically across tasks. `jobObjectCPURateControlInformation` and the `cpuRateControl*` consts are defined once (T3) and used once.
- **Known platform caveat:** Tasks 3–4 tests require a Windows runner; the CI matrix covers this. `GOOS=windows go build ./internal/confine/` typechecks them from any host (T9 step 3).
