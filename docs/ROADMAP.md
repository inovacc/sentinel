# Sentinel Roadmap

## Phase 1: Foundation (Complete)
- [x] Project scaffold (go.mod, Taskfile, CLAUDE.md, Cobra CLI)
- [x] Protobuf service definitions (Exec, FileSystem, Fleet, Capture, Session)
- [x] CA system (P-256 ECDSA, Syncthing-style device IDs, role extensions)
- [x] Sandbox engine (path validation, allowlist, traversal prevention)
- [x] Session manager (SQLite persistence, checkpoints, heartbeat, crash recovery)
- [x] gRPC server with mTLS + RBAC interceptor
- [x] Supervisor pattern (monitor/worker, signal handling, PID file, log rotation)

## Phase 2: Core Sandbox + Exec
- [ ] ExecService gRPC implementation (command execution with timeout + streaming)
- [ ] FileSystemService implementation (read, write, list, glob, grep)
- [ ] Platform-specific shell resolution (bash/cmd/powershell)
- [ ] Wire `sentinel serve` command to start full daemon

## Phase 3: Sessions
- [ ] SessionService gRPC implementation
- [ ] Auto-checkpoint on exec and file write
- [ ] Heartbeat monitoring goroutine
- [ ] Session recovery on daemon startup

## Phase 4: Security + Pairing
- [ ] `sentinel ca init` full implementation
- [ ] Device pairing flow (discover, request, accept/reject)
- [ ] mDNS LAN discovery
- [ ] Trusted peers management (SQLite)

## Phase 5: MCP Integration
- [ ] MCP stdio server with go-sdk
- [ ] Tool definitions mapping to gRPC services
- [ ] Device routing (local vs remote via device_id)
- [ ] Session tools for Claude Code

## Phase 6: Fleet + Upload
- [ ] Fleet registry (SQLite)
- [ ] Health monitoring loop
- [ ] Chunked file upload/download
- [ ] Project upload to sandbox

## Phase 7: Docker Connector (DinD)
- [ ] Docker-in-Docker (DinD) connector for isolated test environments
- [ ] Launch ephemeral Docker containers per test session
- [ ] Mount project from sandbox into container
- [ ] Execute tests inside container with streaming output
- [ ] Support multiple base images (Go, Node, Python, Rust, etc.)
- [ ] Container lifecycle management (create, start, exec, stop, remove)
- [ ] Resource limits (CPU, memory, disk) per container
- [ ] Network isolation between test containers
- [ ] gRPC `DockerService` with RPCs: CreateContainer, ExecInContainer, StreamLogs, DestroyContainer
- [ ] MCP tools: `docker.create`, `docker.exec`, `docker.logs`, `docker.destroy`

## Phase 8: Screen Capture
- [ ] Electron `sentinel-eye` app
- [ ] IPC bridge (daemon <-> Electron via localhost TCP)
- [ ] CaptureService gRPC implementation
- [ ] OS-level fallback capture (screencapture/nircmd)

## Phase 9: Polish
- [ ] Cross-platform testing (Windows, Linux, macOS)
- [ ] Windows service / systemd unit installation
- [ ] Configuration validation
- [ ] Documentation (README, ARCHITECTURE, ADRs)
