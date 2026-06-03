# OS Sandbox (Process Confinement) — Design

**Date:** 2026-06-03
**Status:** Approved (design); ready for implementation planning
**Threats addressed:** T5.1 (CRITICAL — allowlisted binary is a code-execution vector), with secondary coverage of T5.3 (per-process resource exhaustion) and the existing worker-orphan leak.

## Problem

Sentinel's sandbox today is **access-control only**: `internal/sandbox` validates paths
(`CheckRead/Write/Delete`) and gates executables against an allowlist (`CheckExec`). Once a
process is spawned — via `exec.Runner` (`buildCmd` → `cmd.Run/Start`) or `worker.Pool.Spawn` —
it runs with the daemon's full OS rights: any filesystem, any network, any syscall.

The allowlist is necessary but **not sufficient**: every allowlisted interpreter/toolchain is
itself an arbitrary-code vector (`python -c "..."`, `node -e`, `go run`, `bash -c`). A hijacked
tool call can read secrets outside the sandbox, exfiltrate over the network, or damage the host.
This is threat **T5.1**, the only open CRITICAL in the threat model, currently mitigated by
nothing but the allowlist.

## Goals (v1)

- Confine every process Sentinel spawns on **Windows** (the primary deployment target) with
  OS-level limits the in-process allowlist cannot provide.
- **Privilege drop:** spawned processes run under a restricted token (no admin SID, dangerous
  privileges removed) so a hijacked binary cannot damage the host.
- **Resource & process containment:** cap memory, CPU, and active-process count (fork-bomb
  resistance); guarantee teardown of the whole process tree (also fixes the current worker
  orphan leak).
- **Fail-closed on Windows:** if confinement cannot be applied, the exec is refused.
- Zero new runtime dependencies; keep `os/exec`; minimal blast radius on existing code.

## Non-goals (v1) — YAGNI

- **No FS/network jail on Windows.** Filesystem stays governed by the existing path-allowlist;
  network is not gated. A real FS/network jail (Windows AppContainer / lowbox) is **v3**, opt-in,
  because it requires per-tool capability tuning and risks breaking go/git/python.
- **No native confinement on Linux/macOS in v1.** Those platforms run with a no-op confiner that
  emits a prominent "unconfined exec" warning + security event until v2.
- **No container-per-exec.** Reusing the Docker connector for ephemeral-container isolation is the
  strongest tier but requires Docker on every node; deferred to v3.

## Architecture

### New package: `internal/confine`

A single-purpose, platform-split package. One job: confine a process.

```go
// Confiner applies OS-level confinement to processes Sentinel spawns.
type Confiner interface {
    // Prepare configures confinement that must be set at creation time
    // (restricted token, creation flags). Called before cmd.Start().
    Prepare(cmd *osexec.Cmd) error

    // Confine attaches post-creation limits to a started process
    // (Job Object assignment). Called immediately after cmd.Start().
    Confine(p *os.Process) error

    // Supported reports whether real confinement is in effect on this
    // platform. False for the v1 no-op platforms (Linux/macOS).
    Supported() bool

    // Close releases confiner-held OS handles (e.g. the Job Object).
    Close() error
}
```

- `confine_windows.go` — the real implementation.
- `confine_other.go` (build tag `!windows`) — no-op: `Prepare`/`Confine` return nil, `Supported()`
  returns false.
- `New(cfg Config, logger) (Confiner, error)` — constructed once at daemon startup and shared.

### Windows mechanism (v1)

1. **Restricted token** (`golang.org/x/sys/windows`):
   - `CreateRestrictedToken` on the daemon's token: disable the local-admin SID, remove dangerous
     privileges (e.g. `SeDebugPrivilege`, `SeTcbPrivilege`, `SeLoadDriverPrivilege`,
     `SeTakeOwnershipPrivilege`).
   - Built once at startup; passed per-spawn via `cmd.SysProcAttr.Token`, so `os/exec` performs
     `CreateProcessAsUser` with the de-privileged token at creation time.
2. **Job Object** (`CreateJobObject` + `SetInformationJobObject` with
   `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` and `JOBOBJECT_CPU_RATE_CONTROL_INFORMATION`):
   - `JOB_OBJECT_LIMIT_ACTIVE_PROCESS` → max active processes (fork-bomb cap).
   - `JOB_OBJECT_LIMIT_PROCESS_MEMORY` / `JOB_OBJECT_LIMIT_JOB_MEMORY` → memory cap.
   - CPU-rate control → CPU cap.
   - `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` → all processes die when the job handle closes (daemon
     exit or per-exec cleanup); eliminates orphans, including today's worker leak.
   - Assigned via `AssignProcessToJobObject` immediately after `cmd.Start()`.

**Known limitation (documented, deferred):** assigning after `Start()` leaves a sub-millisecond
window in which the child could spawn a grandchild before assignment. Acceptable for v1 because the
restricted token already constrains what that child can do; hardening via `CREATE_SUSPENDED` →
assign → resume is a v1.1 follow-up (it requires raw `CreateProcess` to obtain the thread handle,
a larger change `os/exec` does not expose).

### Enforcement posture

- **Windows:** `Prepare`/`Confine` errors are fatal to the exec — the call returns an error, the
  process is not run (or is killed if already started), and a security event is logged. The
  control is **mandatory where supported**.
- **Non-Windows (no-op confiner):** the process runs, but the spawn path logs a prominent
  `unconfined exec` warning + security event (one per exec) until v2 lands native support.
- A posture helper centralizes this decision: `func decide(supported bool, applyErr error) (refuse bool, warn bool)`.

### Integration points

Both process-spawn sites route through the confiner:

- `internal/exec/exec.go` — `buildCmd` calls `Prepare`; `Run`/`runBackground`/`RunStream` call
  `Confine` immediately after `Start()`, and apply the posture decision.
- `internal/worker/pool.go` — `Spawn` does the same around its `cmd.Start()`.

The `Runner` and `Pool` each take a `Confiner` (constructor injection), defaulting to the daemon's
shared confiner. The daemon wires one confiner in `cmd/serve.go` (`registerServices` / pool
construction) and `Close()`s it on shutdown.

### Configuration

New `settings` block (additive, schema-version bump + migration):

```yaml
confine:
  enabled: true          # master switch; false runs unconfined (logged loudly) for debug/trusted
  max_memory_mb: 1024    # per-process / job memory cap (0 = unlimited)
  cpu_percent: 80        # CPU-rate cap (0 = unlimited)
  max_processes: 64      # active-process cap (0 = unlimited)
```

Defaults are conservative-but-workable for go/git/python builds. `enabled: false` is an explicit
escape hatch, logged as a security-relevant warning on startup.

## Testing strategy

- **Windows-tagged integration tests** (run by the existing cross-platform CI matrix):
  - a child that allocates beyond `max_memory_mb` is killed by the job;
  - spawning beyond `max_processes` is rejected;
  - `KILL_ON_JOB_CLOSE` tears down a child tree when the confiner/job closes;
  - a spawned process cannot exercise a dropped privilege (token is restricted).
- **Cross-platform unit tests:** the no-op confiner reports `Supported()==false`; the posture
  helper returns `warn` (not `refuse`) when unsupported, and `refuse` on a Windows apply error.
- **Regression:** existing `exec`/`worker` suites pass with the confiner wired (default config).

## Phasing

- **v1 (this phase):** Windows Job Object + restricted token; fail-closed on Windows; no-op + warn
  elsewhere. Closes T5.1 on Windows, plus T5.3 (resource caps) and the worker-orphan leak.
- **v2:** Linux native — Landlock (FS) + seccomp (syscall) + optional network namespace — flips the
  Unix confiner from warn → enforced.
- **v3 (opt-in stronger):** Windows AppContainer / lowbox FS+network jail; container-per-exec via
  the Docker connector for maximum isolation.

## Risks & open questions

- **`os/exec` + token:** confirm `SysProcAttr.Token` reliably yields `CreateProcessAsUser` with our
  restricted token across supported Windows versions; if stdio capture interacts badly, fall back to
  a thin `CreateProcessAsUser` wrapper in the Windows confiner.
- **Default limits:** `max_memory_mb`/`cpu_percent` defaults may need tuning against real go/python
  builds to avoid false kills; treat the first release defaults as provisional and easily overridden.
- **Per-exec vs shared Job Object:** v1 uses one shared job for kill-on-daemon-exit simplicity;
  if per-exec teardown granularity is needed (kill one exec's tree without others), move to a
  job-per-exec — flagged for the plan.
```
