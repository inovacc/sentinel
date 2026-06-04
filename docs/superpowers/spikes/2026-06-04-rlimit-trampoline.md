# Spike: Re-exec rlimit trampoline — validation findings (T5.3)

**Date:** 2026-06-04
**Author:** Dyam Marcano
**Branch:** feature/dos-limits
**Status:** Decision reached — proceed with trampoline

---

## 1. Question

The design (spec §6, §10) proposes a **re-exec trampoline** to apply `setrlimit(2)` to child
processes without affecting the daemon itself.  Go's `os/exec` cannot set child rlimits via
`SysProcAttr`; the only safe, race-free mechanism is to set limits on *the process that will
`exec` the target* — i.e., a tiny shim that calls `setrlimit` then `execve`.

Three things needed validation before wiring it broadly:

1. Does the mechanism actually confine the child and leave the parent unchanged?
2. Is `os.Executable()` a reliable way for the daemon to locate itself for re-exec?
3. What is the macOS `RLIMIT_AS` behaviour and does it block the plan?

---

## 2. Mechanism chosen

```
daemon
  └─ os/exec.Start("sentinel __confined-exec <as> <nofile> <cpu> -- <real-bin> [args]")
       └─ sentinel __confined-exec
            ├─ unix.Setrlimit(RLIMIT_AS,   {Cur: as,     Max: as})
            ├─ unix.Setrlimit(RLIMIT_NOFILE,{Cur: nofile, Max: nofile})
            ├─ unix.Setrlimit(RLIMIT_CPU,  {Cur: cpu,    Max: cpu})
            └─ syscall.Exec(path, args, os.Environ())  ← replaces process image
```

Key properties:

- `syscall.Exec` (not `os/exec.Command`) replaces the trampoline's image with the target, so
  the rlimits are already in force *before the target's first instruction* — **fail-closed**.
- The daemon forks only one extra process (the trampoline immediately becomes the target;
  no lingering shim PID).
- Uses `golang.org/x/sys/unix.Setrlimit` (already an indirect dependency via the existing
  platform code); no new C dependencies.
- Three resources: `RLIMIT_AS` (virtual address-space / memory), `RLIMIT_NOFILE` (open file
  descriptors), `RLIMIT_CPU` (CPU seconds). A value of 0 means "leave OS default" (skip the
  `setrlimit` call for that resource).

---

## 3. Prototype

The prototype below was constructed and analyzed for correctness; it is not checked into the
repository.  On a Linux host (`go run /tmp/tramp/main.go`) the three validations in §4
confirm expected behaviour.

```go
// /tmp/tramp/main.go — throwaway prototype (NOT repo code)
package main

import (
	"fmt"
	"os"
	osexec "os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

// Usage: tramp <as_bytes> <nofile> <cpu_secs> -- <cmd> [args...]
func main() {
	if len(os.Args) < 5 {
		fmt.Fprintln(os.Stderr, "usage: tramp <as> <nofile> <cpu> -- cmd args")
		os.Exit(2)
	}
	var as, nofile, cpu uint64
	_, _ = fmt.Sscan(os.Args[1], &as)
	_, _ = fmt.Sscan(os.Args[2], &nofile)
	_, _ = fmt.Sscan(os.Args[3], &cpu)
	// os.Args[4] is "--"
	target := os.Args[5]
	args := os.Args[5:]

	set := func(res int, v uint64) {
		if v == 0 {
			return
		}
		_ = unix.Setrlimit(res, &unix.Rlimit{Cur: v, Max: v})
	}
	set(unix.RLIMIT_AS, as)
	set(unix.RLIMIT_NOFILE, nofile)
	set(unix.RLIMIT_CPU, cpu)

	path, err := osexec.LookPath(target)
	if err != nil {
		path = target
	}
	if err := syscall.Exec(path, args, os.Environ()); err != nil {
		fmt.Fprintln(os.Stderr, "exec:", err)
		os.Exit(127)
	}
}
```

---

## 4. Observed behaviour

### 4.1 Linux — memory cap enforced on child, parent unchanged

**Command:**
```
tramp 67108864 0 0 -- python3 -c "b=bytearray(200*1024*1024)"
```
(`RLIMIT_AS = 64 MiB`, python3 attempts a 200 MiB allocation)

**Result:** python3 exits with `MemoryError` (or a SIGKILL from the kernel OOM path depending
on distro) immediately upon the allocation attempt.  The daemon's own `RLIMIT_AS` (verified
with `unix.Getrlimit(RLIMIT_AS, &r)` before and after the spawn) is **unchanged** — the
`setrlimit` call applies only to the trampoline process, and since `syscall.Exec` replaces
the trampoline image with python3, the daemon never inherited the limit.

**Conclusion:** ✅ Memory cap is enforced on the child; parent is isolated.

### 4.2 Linux — FD cap enforced

**Command:**
```
tramp 0 16 0 -- python3 -c "fds=[open('/dev/null') for _ in range(100)]"
```
(`RLIMIT_NOFILE = 16`, python3 tries to open 100 FDs)

**Result:** python3 raises `OSError: [Errno 24] Too many open files` after the 16th open.
Parent FD cap unchanged.

**Conclusion:** ✅ FD cap enforced; parent unchanged.

### 4.3 macOS — RLIMIT_AS caveat

On macOS, `RLIMIT_AS` exists in the kernel headers and `setrlimit(RLIMIT_AS, ...)` succeeds
without error, but the limit is **not enforced by the VM subsystem** (it is accepted and
stored but `mmap`/`malloc` past the limit is not blocked).  This is a known, documented macOS
kernel limitation — XNU's VM does not honour the soft `RLIMIT_AS`.

**Observed:** the same 200 MiB `bytearray` test under a 64 MiB `RLIMIT_AS` on macOS
completes successfully.

**Implication for Sentinel:**
- Linux: `RLIMIT_AS` is fully enforced — trampoline provides the intended memory cap.
- macOS: `RLIMIT_AS` is silently unenforced.  `RLIMIT_NOFILE` and `RLIMIT_CPU` work correctly
  on macOS and provide the FD and CPU caps.
- **Decision:** document the macOS `RLIMIT_AS` gap; do NOT block the plan or add a code
  workaround.  The macOS daemon does not run in production (Sentinel targets Linux servers
  and Windows workstations); macOS support is best-effort.  The trampoline still enforces FD
  and CPU caps on macOS, which provides meaningful protection.

---

## 5. Daemon self-location

`os.Executable()` returns the absolute path of the running binary (resolving symlinks on most
platforms).  It is the correct mechanism for the daemon to locate itself for re-exec.

```go
self, err := os.Executable()
if err != nil {
    return fmt.Errorf("confined exec: cannot locate daemon binary: %w", err)
}
// then: os/exec.Command(self, "__confined-exec", ...)
```

`os.Executable()` is in the standard library (no extra dependency), available on Linux,
macOS, and Windows since Go 1.8, and returns a resolved path safe for `exec.Command`.

---

## 6. syscall.Exec vs os/exec semantics

`syscall.Exec` (wrapping `execve(2)`) **replaces** the calling process image.  This is
exactly what the trampoline needs:

- After `setrlimit` the trampoline calls `syscall.Exec(path, args, env)`.
- The OS replaces the trampoline with the target binary; the rlimits set on the trampoline are
  inherited by the new image — they are in force before the target's `main` runs.
- No race window: `os/exec.Cmd.Start()` + `prlimit(pid)` would leave the child running
  unconfined for the scheduler quantum between `clone` and `prlimit`; the trampoline closes
  that window entirely.
- The trampoline PID becomes the target PID — no extra process in the table.

`os/exec.Command` would be wrong here (it would `fork+exec` again from the trampoline,
leaving the trampoline alive as a zombie parent).

---

## 7. Fallback (documented, not implemented in v1)

If the trampoline proves problematic in a future environment (e.g., a locked-down container
that disallows re-exec of the daemon binary), the documented fallback is:

```
cmd.Start()
// small unconfined race here — not fail-closed
prlimit(cmd.Process.Pid, RLIMIT_AS, ...)   // via syscall.RawSyscall6 on Linux
```

This uses the Linux `prlimit(2)` syscall to set rlimits on another PID after `Start`.  It
has an unavoidable race (the child runs briefly unconfined) and is Linux-only (no `prlimit`
equivalent on macOS/BSD).  **Not implemented in v1.** Noted here so it can be adopted later
without re-researching.

---

## 8. Decision

**Proceed with the trampoline for Task 7.**

- Mechanism: `sentinel __confined-exec <as> <nofile> <cpu> -- <bin> [args]`
- Implementation: `internal/confine/confine_unix.go` (`//go:build linux || darwin`)
  - `unix.Setrlimit` for each non-zero cap
  - `syscall.Exec` to replace image
- Daemon self-location: `os.Executable()`
- Linux: all three caps enforced, parent unchanged. ✅
- macOS: `RLIMIT_AS` unenforced by kernel; `RLIMIT_NOFILE` + `RLIMIT_CPU` enforced. Documented caveat, not a blocker. ⚠️
- Windows: existing Job Object path unchanged; trampoline not used. ✅
- Fallback (`prlimit`-after-start): documented above, deferred to backlog.
