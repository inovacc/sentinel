# Sentinel Roadmap

## Phase 1: Foundation (Complete)
- [x] Project scaffold (go.mod, Taskfile, CLAUDE.md, Cobra CLI)
- [x] Protobuf service definitions (Exec, FileSystem, Fleet, Capture, Session, Payload, Worker)
- [x] CA system (P-256 ECDSA, Syncthing-style device IDs, role extensions)
- [x] Sandbox engine (path validation, allowlist, traversal prevention)
- [x] Session manager (SQLite persistence, checkpoints, heartbeat, crash recovery)
- [x] gRPC server with mTLS + RBAC interceptor
- [x] Supervisor pattern (monitor/worker, signal handling, PID file, log rotation)

## Phase 2: Core Sandbox + Exec (Complete)
- [x] ExecService gRPC implementation (command execution with timeout + streaming)
- [x] FileSystemService implementation (read, write, list, glob, grep)
- [x] Platform-specific shell resolution (bash/cmd/powershell)
- [x] Wire `sentinel serve` command to start full daemon
- [x] Background exec for detached processes (--background flag)

## Phase 3: Sessions (Complete)
- [x] SessionService gRPC implementation
- [x] Auto-checkpoint on exec
- [x] Auto-checkpoint on file write
- [x] Heartbeat monitoring goroutine
- [x] Session recovery on daemon startup

## Phase 4: Security + Pairing (Complete)
- [x] `sentinel ca init/show/export/sign` full implementation
- [x] Two-phase transport: Syncthing-key bootstrap → mTLS transition
- [x] Device pairing flow (bootstrap connect, accept/reject)
- [x] mDNS LAN discovery (`sentinel discover`)
- [x] Fleet registry (SQLite) with trusted peers management
- [x] Bootstrap port open alongside mTLS for continuous pairing

## Phase 5: MCP Integration (Complete)
- [x] MCP stdio server with go-sdk (14+ tools)
- [x] Tool definitions mapping to gRPC services
- [x] Device routing (local vs remote via device_id)
- [x] Session tools for Claude Code
- [x] Payload tool with device routing
- [x] Worker MCP tools (spawn, list, get, kill)

## Phase 6: Fleet + Upload (Complete)
- [x] Fleet registry (SQLite) — pair list/accept/reject/fleet list/status/remove
- [x] Health monitoring loop
- [x] Chunked file upload (`sentinel upload`)
- [x] Remote file operations (`sentinel ls`)
- [x] gRPC client with mTLS (`internal/client`)

## Phase 7: Worker Pool (Complete)
- [x] Worker pool with parallel task execution
- [x] Auto-reaper: kill stale/hung workers after timeout
- [x] SQLite persistence with stdout/stderr capture
- [x] Crash recovery: mark orphaned workers as stale
- [x] WorkerService gRPC (6 RPCs)
- [x] CLI: sentinel worker spawn/list/get/kill/killall

## Phase 8: Structured Payloads (Complete)
- [x] PayloadService gRPC (Send/SendStream)
- [x] Handler registry with built-in actions (ping, sysinfo, env.get, echo)
- [x] Custom handler registration
- [x] CLI: sentinel payload
- [x] MCP payload tool with device routing

## Phase 9: Screen Capture (Partial)
- [ ] Electron `sentinel-eye` app
- [ ] IPC bridge (daemon <-> Electron via localhost TCP)
- [ ] CaptureService gRPC implementation
- [x] OS-level fallback capture (PowerShell/screencapture/ImageMagick)
- [x] CLI: sentinel capture --json

## Phase 10: Docker Connector (DinD)
- [ ] Docker client integration
- [ ] Launch ephemeral containers per test session
- [ ] Mount project from sandbox into container
- [ ] Execute tests inside container with streaming output
- [ ] Support multiple base images (Go, Node, Python, Rust, etc.)
- [ ] Container lifecycle management (create, start, exec, stop, remove)
- [ ] Resource limits (CPU, memory, disk) per container
- [ ] DockerService gRPC + MCP tools

## Phase 11: Polish
- [x] Windows service / systemd unit installation
- [x] Plain text startup banner (--json for JSON)
- [x] CI/CD workflow (GitHub Actions — cross-platform matrix + lint)
- [x] Config validation on startup
- [ ] Relay server for NAT traversal
- [ ] Cross-platform testing verification
- [ ] Web dashboard for fleet management
- [ ] Auto-update mechanism across fleet
- [ ] Comprehensive documentation update
