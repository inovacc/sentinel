# Sentinel

Secure remote REPL daemon for [Claude Code](https://claude.com/claude-code). Lets Claude Code remotely access and manage a fleet of machines (local + VMs) through a non-destructive sandbox with mTLS security.

## Features

- **Two-phase transport**: Syncthing-style bootstrap handshake, then mTLS for production
- **Non-destructive sandbox**: Write/delete only within sandbox dir, read via allowlist
- **Resumable sessions**: SQLite-persisted sessions with checkpoints and crash recovery
- **Certificate-based auth**: Syncthing-style device IDs (SHA-256 of cert, base32 with Luhn)
- **RBAC**: admin/operator/reader roles embedded in X.509 certificate extensions
- **MCP integration**: Claude Code connects via MCP stdio server with 19 tools
- **Worker pool**: Background process management with spawn/list/get/kill
- **Payload routing**: Structured JSON payload dispatch with pluggable handlers
- **Screen capture**: Screenshot displays locally or on remote devices
- **Fleet discovery**: mDNS service discovery — the server advertises its LAN address in time-boxed windows (at startup and after a lost connection)
- **Cross-platform**: Windows, Linux, macOS

## Quick Start

```bash
# Install
go install github.com/inovacc/sentinel@latest

# Or build from source
go build -o sentinel .

# Initialize CA and device identity
sentinel ca init

# Verify the install (creates data dirs + config, checks CA/cert/ports)
sentinel doctor --fix

# Start the daemon (foreground)
sentinel serve

# Or start MCP server for Claude Code
sentinel mcp
```

## Claude Code Integration

Add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "sentinel": {
      "command": "sentinel",
      "args": ["mcp"]
    }
  }
}
```

### Available MCP Tools

| Tool | Description |
|------|-------------|
| `exec` | Execute commands in the sandbox |
| `read_file` | Read files from sandbox or allowlisted paths |
| `write_file` | Write files to sandbox |
| `list_dir` | List directory contents |
| `glob` | Pattern match files |
| `grep` | Search file contents with regex |
| `delete_file` | Delete files within sandbox |
| `session_create` | Start a tracked session |
| `session_list` | List sessions (filter by status) |
| `session_resume` | Resume interrupted session with full state |
| `session_pause` | Pause with checkpoint |
| `session_status` | Get session details |
| `session_destroy` | Clean up a session |
| `payload` | Send structured JSON payload to a device |
| `worker_spawn` | Spawn a background worker process |
| `worker_list` | List workers (filter by status) |
| `worker_get` | Get worker details and output |
| `worker_kill` | Kill a running worker |
| `screenshot` | Capture a screenshot of a display |

## CLI Commands

```
sentinel serve            Start gRPC daemon (foreground)
sentinel server start     Start as background service
sentinel server stop      Stop background service
sentinel mcp              Start MCP stdio server
sentinel ca init          Initialize Certificate Authority
sentinel ca show          Show device identity
sentinel ca export        Export CA cert for sharing
sentinel ca sign          Sign a CSR
sentinel pair accept      Accept device pairing
sentinel fleet list       List fleet devices
sentinel exec             Execute remote command
sentinel upload           Upload project to sandbox
sentinel capture          Screenshot remote device
sentinel discover         Discover devices on local network
sentinel bootstrap connect <addr>   Pair with a discovered server (host:7399)
sentinel doctor           Diagnose the install (config, CA, cert, ports)
sentinel doctor --fix     Apply safe fixes (create dirs, migrate config)
sentinel ls               List remote directory
sentinel payload          Send payload to device
sentinel worker spawn     Spawn background worker
sentinel worker list      List workers
sentinel worker get       Get worker details
sentinel worker kill      Kill a running worker
sentinel version          Show version info
```

## Common Workflows

### First-time setup

```bash
sentinel ca init          # generate the CA + this device's admin certificate
sentinel doctor --fix     # create data dirs + config.yaml, verify everything
sentinel serve            # start the daemon
```

### LAN discovery & pairing (two machines)

When `serve` starts, the server advertises itself via mDNS (`_sentinel._tcp`) on
its LAN address for a 5-minute window, re-opening it whenever a connection is
lost. To pair a new client:

```bash
# Server (machine A):
sentinel serve

# Client (machine B):
sentinel discover                              # finds A -> device_id + 192.168.x.x:7399
sentinel bootstrap connect 192.168.x.x:7399    # handshake, receive a CA-signed cert

# Server (machine A): approve the pending device
sentinel pair accept <device-id>

# Client (machine B): now operate over mTLS (:7400)
sentinel exec -- go version
sentinel ls .
sentinel fleet list
```

> **Note:** running `discover` and `serve` on the *same* machine may return
> nothing (multicast usually does not loop back between two local processes,
> especially on Windows). Use two machines, or verify in-process with
> `SENTINEL_TEST_MDNS=1 go test ./internal/discovery/ -run RoundTrip`.

### Health check & maintenance

```bash
sentinel doctor           # report on data dir, config (+ schema version), CA, cert, ports
sentinel doctor --fix     # create missing dirs; migrate the config to the latest schema
```

`doctor` exits non-zero when unresolved problems remain (usable as a
healthcheck). It never generates crypto material — CA/certificate problems are
reported with the exact command to run.

## Configuration

Config lives at `~/.sentinel/config.yaml` (Windows:
`%LOCALAPPDATA%\sentinel\config.yaml`) and is read at daemon startup. Any omitted
field falls back to its default; run `sentinel doctor --fix` to create or migrate
it.

```yaml
version: 1                # schema version (managed by `sentinel doctor`)
listen:
  grpc: ":7400"           # mTLS gRPC (authenticated clients)
  bootstrap: ":7399"      # pairing port (also the address advertised via mDNS)
  metrics: ":7401"        # /metrics endpoint
discovery:
  enabled: true           # advertise on the LAN; set false to stay silent
  window_seconds: 300     # broadcast window length per trigger (5 min)
security:
  auto_accept: false      # true = pair without manual approval (less secure)
sandbox:
  root: ""                # empty = ~/.sentinel/sandbox (write/delete confined here)
logging:
  level: "info"           # debug | info | warn | error
```

The `SENTINEL_DATA_DIR` environment variable overrides the data directory
location; `SENTINEL_SKIP_PUBLIC_IP=1` skips the startup public-IP lookup
(useful for air-gapped hosts).

## Security Model

1. **Bootstrap phase** (port 7399): Self-signed TLS with Syncthing-style device IDs. Certificate exchange and signing happen here.
2. **mTLS phase** (port 7400): CA-signed mutual TLS. Bootstrap port is closed.
3. **Sandbox**: All operations are validated against the allowlist. Write/delete restricted to `~/.sentinel/sandbox/`.
4. **RBAC**: Roles (admin, operator, reader) embedded in certificates. Each gRPC method requires a minimum role.

## Development

```bash
task build          # Build binary
task test           # Run tests
task lint           # Run linter
task proto          # Regenerate protobuf code
task serve          # Run daemon
task mcp            # Run MCP server
```

## License

BSD 3-Clause License
