# Sentinel

Secure remote REPL daemon for Claude Code. Manages a fleet of machines (local + VMs) with mTLS security, sandbox enforcement, and resumable sessions.

## Quick Reference

```bash
task build          # Build binary
task test           # Run tests
task lint           # Run linter
task proto          # Generate protobuf code
task serve          # Start daemon
task mcp            # Start MCP server
task ca:init        # Initialize CA
```

## Architecture

- **Transport:** Two-phase connection lifecycle (see `pkg/transport/`)
  1. **Bootstrap (port 7399):** Syncthing-style self-signed TLS, device ID exchange, certificate signing
  2. **mTLS (port 7400):** CA-signed mutual TLS, bootstrap port closed after transition
  3. **Renewal:** `--renew-certs` flag temporarily reopens bootstrap for cert exchange
- **Auth:** Certificate-based device IDs (Syncthing-style SHA-256 → base32 with Luhn checks)
- **RBAC:** Roles embedded in X.509 custom extension OID (admin, operator, reader)
- **Storage:** SQLite (sessions, fleet registry, settings)
- **Integration:** MCP stdio server for Claude Code

## Project Structure

```
cmd/           # Cobra CLI commands
proto/v1/      # Protobuf service definitions
pkg/
  transport/   # Two-phase transport lifecycle (bootstrap → mTLS)
    transport.go   # Manager: phase detection, transition, renewal
    bootstrap.go   # Server/client for Syncthing-key handshake
    protocol.go    # Wire protocol messages (length-prefixed JSON)
    mtls.go        # mTLS dialer, listener, server config
    store.go       # Certificate persistence to disk
internal/
  api/v1/      # Generated protobuf code
  grpc/        # gRPC server, services, RBAC interceptor
  mcp/         # MCP stdio server + tools
  ca/          # Self-contained CA, device identity
  rbac/        # Role-based access control policy engine
  sandbox/     # Path validation, allowlist, sandbox enforcement
  session/     # Session manager, checkpoints, heartbeat
  exec/        # Command execution engine
  fs/          # File operations, chunked transfer
  fleet/       # Fleet registry, health monitoring
  capture/     # Screenshot coordination, Electron IPC
  supervisor/  # Monitor/worker process management
eye/           # Electron screen capture app
```

## Conventions

- Go 1.23+
- Table-driven tests, 80%+ coverage
- `log/slog` structured JSON logging (always stderr, stdout = MCP/gRPC)
- `errors.Is` / `errors.As` for error comparison
- Inline error checks: `if err := doX(); err != nil { return fmt.Errorf("x: %w", err) }`
- Platform files: `*_windows.go`, `*_linux.go`, `*_darwin.go`

## Safety Rules

- **Sandbox:** Write/delete ONLY under `~/.sentinel/sandbox/`. Read via allowlist.
- **Exec:** Only allowlisted binaries (go, git, npm, python, etc.)
- **Blocked:** `rm -rf /`, `format`, `fdisk`, `mkfs` always denied
- **Path traversal:** All paths resolved to absolute, `../` escape prevented
