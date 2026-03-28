# Sentinel

Secure remote REPL daemon for [Claude Code](https://claude.com/claude-code). Lets Claude Code remotely access and manage a fleet of machines (local + VMs) through a non-destructive sandbox with mTLS security.

## Features

- **Two-phase transport**: Syncthing-style bootstrap handshake, then mTLS for production
- **Non-destructive sandbox**: Write/delete only within sandbox dir, read via allowlist
- **Resumable sessions**: SQLite-persisted sessions with checkpoints and crash recovery
- **Certificate-based auth**: Syncthing-style device IDs (SHA-256 of cert, base32 with Luhn)
- **RBAC**: admin/operator/reader roles embedded in X.509 certificate extensions
- **MCP integration**: Claude Code connects via MCP stdio server with 13 tools
- **Cross-platform**: Windows, Linux, macOS

## Quick Start

```bash
# Install
go install github.com/inovacc/sentinel@latest

# Or build from source
go build -o sentinel .

# Initialize CA and device identity
sentinel ca init

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

## CLI Commands

```
sentinel serve          Start gRPC daemon (foreground)
sentinel server start   Start as background service
sentinel server stop    Stop background service
sentinel mcp            Start MCP stdio server
sentinel ca init        Initialize Certificate Authority
sentinel ca show        Show device identity
sentinel ca export      Export CA cert for sharing
sentinel ca sign        Sign a CSR
sentinel pair accept    Accept device pairing
sentinel fleet list     List fleet devices
sentinel exec           Execute remote command
sentinel upload         Upload project to sandbox
sentinel capture        Screenshot remote device
sentinel version        Show version info
```

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
