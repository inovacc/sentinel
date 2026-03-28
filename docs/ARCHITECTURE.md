# Sentinel Architecture

## System Overview

```
┌──────────────┐     MCP stdio     ┌──────────────┐    gRPC/mTLS    ┌──────────────┐
│  Claude Code │◄──────────────────►│   sentinel   │◄──────────────►│   sentinel   │
│              │                    │   mcp        │                │   daemon     │
└──────────────┘                    └──────────────┘                └──────┬───────┘
                                                                          │
                                                                   ┌──────┴───────┐
                                                                   │ sentinel-eye │
                                                                   │  (Electron)  │
                                                                   └──────────────┘
```

## Component Architecture

### Transport Layer (`pkg/transport/`)

Two-phase connection lifecycle:

```
Phase 1: Bootstrap (port 7399)          Phase 2: mTLS (port 7400)
┌─────────────────────────────┐         ┌─────────────────────────────┐
│ Self-signed TLS             │         │ CA-signed mutual TLS        │
│ Device ID verification      │  ────►  │ RequireAndVerifyClientCert  │
│ Certificate exchange + sign │         │ Bootstrap port CLOSED       │
│ Temporary (24h cert)        │         │ Production communication    │
└─────────────────────────────┘         └─────────────────────────────┘
```

On startup: if mTLS certs exist, skip bootstrap. `--renew-certs` temporarily reopens bootstrap.

### Security Stack

```
┌─────────────────────────────────────┐
│          gRPC Request               │
├─────────────────────────────────────┤
│    mTLS Interceptor                 │  Extract peer cert from TLS
├─────────────────────────────────────┤
│    Role Extraction (ca.ExtractRole) │  Read custom X.509 OID
├─────────────────────────────────────┤
│    RBAC Policy Check                │  Method → minimum role mapping
├─────────────────────────────────────┤
│    Sandbox Enforcement              │  Path validation + allowlist
├─────────────────────────────────────┤
│    Service Handler                  │  Business logic
└─────────────────────────────────────┘
```

### Data Flow

```
                    ┌──────────┐
                    │  SQLite  │
                    │          │
                    │ sessions │
                    │ events   │
                    │ checkpts │
                    └────┬─────┘
                         │
┌────────┐    ┌──────────┴──────────┐    ┌──────────┐
│ Runner │◄──►│   Session Manager   │◄──►│  gRPC    │
│ (exec) │    │                     │    │ Services │
└───┬────┘    │  - Create/Resume    │    └────┬─────┘
    │         │  - Checkpoint       │         │
    │         │  - Heartbeat        │         │
    │         │  - Crash recovery   │    ┌────┴─────┐
┌───┴────┐    └─────────────────────┘    │   MCP    │
│Sandbox │                               │  Server  │
│        │                               │ (stdio)  │
│ - Read │                               └──────────┘
│ - Write│
│ - Exec │
│ - Del  │
└────────┘
```

## Directory Structure

```
sentinel/
├── main.go                          # Entry point
├── cmd/                             # Cobra CLI commands
│   ├── root.go                      # Root command + flag setup
│   ├── serve.go                     # Daemon (wires all services)
│   ├── mcp.go                       # MCP stdio server
│   ├── ca.go                        # CA management
│   └── ...                          # pair, fleet, exec, upload, capture, server, version
├── proto/v1/                        # Protobuf definitions
│   ├── sentinel.proto               # ExecService, FileSystemService
│   ├── fleet.proto                  # FleetService, CaptureService
│   └── session.proto                # SessionService
├── pkg/
│   └── transport/                   # Two-phase transport lifecycle
│       ├── transport.go             # Manager (phase detection, transition)
│       ├── bootstrap.go             # Syncthing-key handshake
│       ├── protocol.go              # Wire protocol (length-prefixed JSON)
│       ├── mtls.go                  # mTLS dialer/listener
│       └── store.go                 # Certificate persistence
├── internal/
│   ├── api/v1/                      # Generated protobuf Go code
│   ├── grpc/                        # gRPC server + service implementations
│   │   ├── server.go                # mTLS server setup
│   │   ├── interceptor.go           # RBAC auth interceptor
│   │   ├── exec_service.go          # ExecService impl
│   │   ├── fs_service.go            # FileSystemService impl
│   │   └── session_service.go       # SessionService impl
│   ├── mcp/                         # MCP stdio server
│   │   └── server.go                # 13 tools for Claude Code
│   ├── ca/                          # Certificate Authority
│   │   ├── ca.go                    # P-256 ECDSA CA
│   │   ├── identity.go              # Syncthing-style device IDs
│   │   └── role.go                  # X.509 role extension
│   ├── rbac/                        # Role-based access control
│   ├── sandbox/                     # Non-destructive sandbox engine
│   ├── session/                     # Session manager (SQLite)
│   ├── exec/                        # Command execution engine
│   ├── fs/                          # File operations engine
│   ├── supervisor/                  # Monitor/worker process pattern
│   ├── settings/                    # YAML configuration
│   ├── datadir/                     # Platform data directories
│   ├── serverinfo/                  # PID file management
│   └── logrotate/                   # Rotating log writer
└── eye/                             # Electron screen capture (future)
```

## RBAC Role Matrix

| gRPC Method | admin | operator | reader |
|-------------|-------|----------|--------|
| Exec, ExecStream | x | x | |
| WriteFile, Upload, Delete | x | x | |
| ReadFile, ListDir, Glob, Grep, Download | x | x | x |
| Session Create/Resume/Pause/Checkpoint | x | x | |
| Session Status/List/Heartbeat | x | x | x |
| Session Destroy | x | | |
| Fleet Register, AcceptPairing | x | | |
| Fleet ListDevices, DeviceStatus, Health | x | x | x |
| Screenshot, CaptureWindow, ListDisplays | x | x | x |
