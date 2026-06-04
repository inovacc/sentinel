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

# context-mode — MANDATORY routing rules

You have context-mode MCP tools available. These rules are NOT optional — they protect your context window from flooding. A single unrouted command can dump 56 KB into context and waste the entire session.

## BLOCKED commands — do NOT attempt these

### curl / wget — BLOCKED
Any Bash command containing `curl` or `wget` is intercepted and replaced with an error message. Do NOT retry.
Instead use:
- `ctx_fetch_and_index(url, source)` to fetch and index web pages
- `ctx_execute(language: "javascript", code: "const r = await fetch(...)")` to run HTTP calls in sandbox

### Inline HTTP — BLOCKED
Any Bash command containing `fetch('http`, `requests.get(`, `requests.post(`, `http.get(`, or `http.request(` is intercepted and replaced with an error message. Do NOT retry with Bash.
Instead use:
- `ctx_execute(language, code)` to run HTTP calls in sandbox — only stdout enters context

### WebFetch — BLOCKED
WebFetch calls are denied entirely. The URL is extracted and you are told to use `ctx_fetch_and_index` instead.
Instead use:
- `ctx_fetch_and_index(url, source)` then `ctx_search(queries)` to query the indexed content

## REDIRECTED tools — use sandbox equivalents

### Bash (>20 lines output)
Bash is ONLY for: `git`, `mkdir`, `rm`, `mv`, `cd`, `ls`, `npm install`, `pip install`, and other short-output commands.
For everything else, use:
- `ctx_batch_execute(commands, queries)` — run multiple commands + search in ONE call
- `ctx_execute(language: "shell", code: "...")` — run in sandbox, only stdout enters context

### Read (for analysis)
If you are reading a file to **Edit** it → Read is correct (Edit needs content in context).
If you are reading to **analyze, explore, or summarize** → use `ctx_execute_file(path, language, code)` instead. Only your printed summary enters context. The raw file content stays in the sandbox.

### Grep (large results)
Grep results can flood context. Use `ctx_execute(language: "shell", code: "grep ...")` to run searches in sandbox. Only your printed summary enters context.

## Tool selection hierarchy

1. **GATHER**: `ctx_batch_execute(commands, queries)` — Primary tool. Runs all commands, auto-indexes output, returns search results. ONE call replaces 30+ individual calls.
2. **FOLLOW-UP**: `ctx_search(queries: ["q1", "q2", ...])` — Query indexed content. Pass ALL questions as array in ONE call.
3. **PROCESSING**: `ctx_execute(language, code)` | `ctx_execute_file(path, language, code)` — Sandbox execution. Only stdout enters context.
4. **WEB**: `ctx_fetch_and_index(url, source)` then `ctx_search(queries)` — Fetch, chunk, index, query. Raw HTML never enters context.
5. **INDEX**: `ctx_index(content, source)` — Store content in FTS5 knowledge base for later search.

## Subagent routing

When spawning subagents (Agent/Task tool), the routing block is automatically injected into their prompt. Bash-type subagents are upgraded to general-purpose so they have access to MCP tools. You do NOT need to manually instruct subagents about context-mode.

## Output constraints

- Keep responses under 500 words.
- Write artifacts (code, configs, PRDs) to FILES — never return them as inline text. Return only: file path + 1-line description.
- When indexing content, use descriptive source labels so others can `ctx_search(source: "label")` later.

## ctx commands

| Command | Action |
|---------|--------|
| `ctx stats` | Call the `ctx_stats` MCP tool and display the full output verbatim |
| `ctx doctor` | Call the `ctx_doctor` MCP tool, run the returned shell command, display as checklist |
| `ctx upgrade` | Call the `ctx_upgrade` MCP tool, run the returned shell command, display as checklist |
