# Contributing to Sentinel

Thanks for your interest in Sentinel — a secure remote REPL daemon for Claude Code (mTLS
fleet management, sandbox enforcement, resumable sessions). This guide covers the local
workflow and the conventions the project expects.

## Prerequisites

- **Go 1.26+**
- [**Task**](https://taskfile.dev) (preferred task runner — see `Taskfile.yml`)
- `golangci-lint` (for linting)
- `protoc` + the Go plugins (only if you change `proto/v1/*.proto`)

## Common tasks

```bash
task build      # Build the binary
task test       # Run the test suite
task lint       # golangci-lint run --fix ./...
task proto      # Regenerate protobuf code
task serve      # Start the daemon
task ca:init    # Initialize the local CA
```

Run `task --list` for the full set.

## Development workflow

1. **Branch** off `main` (`feat/...`, `fix/...`, `hardening/...`).
2. **Test-driven development is expected.** Write a failing test first, watch it fail, then
   write the minimal code to pass. Tests are table-driven; aim for meaningful coverage of new
   code (the security-critical packages are held to a high bar).
3. **Keep the gates green** before pushing:
   ```bash
   go build ./...
   go vet ./...
   go test ./...
   golangci-lint run ./... --timeout=5m
   GOOS=linux go build ./...   # cross-build (platform-specific files exist)
   ```
4. **Security tooling** runs in CI (`govulncheck`, `gosec`, `gitleaks`, `osv-scanner`) — run
   `govulncheck ./...` locally for dependency advisories before opening a PR.

## Code conventions

- `log/slog` structured JSON logging — **always to stderr** (stdout is reserved for
  MCP/gRPC).
- Compare errors with `errors.Is` / `errors.As`, never `==`.
- Inline error checks: `if err := doX(); err != nil { return fmt.Errorf("x: %w", err) }`.
- Platform-specific files use the `_windows.go` / `_linux.go` / `_darwin.go` / `_unix.go`
  suffixes (and matching build tags).
- Follow the hexagonal layout: `cmd/` (Cobra CLI), `internal/` (domain), `pkg/` (reusable).

## Safety rules (enforced by the sandbox)

Sentinel executes untrusted commands behind a sandbox. When working on exec/fs/confinement
code, preserve these invariants:

- Write/delete only under `~/.sentinel/sandbox/`; reads go through the allowlist.
- Only allowlisted binaries may be executed; `rm -rf /`, `format`, `fdisk`, `mkfs` are always
  denied.
- All paths are resolved to absolute and checked against `../` traversal escape.
- New OS-level enforcement is **fail-closed** on supported platforms.

## Commits & pull requests

- **Conventional Commits** (`feat:`, `fix:`, `docs:`, `chore:`, `test:`, `refactor:`, …),
  optionally scoped (`feat(audit): …`).
- One logical change per commit; keep history readable.
- PRs should describe **what** changed and **how it was verified** (the gate commands above).
- Update `CHANGELOG.md` under `[Unreleased]` and, for security-relevant changes,
  `docs/security/THREAT-MODEL.md`.

## Reporting security issues

Please do **not** open public issues for vulnerabilities — see [`SECURITY.md`](SECURITY.md).
