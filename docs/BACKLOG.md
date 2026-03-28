# Sentinel Backlog

## Features

### Docker Connector (DinD) - Priority: High
Launch Docker-in-Docker containers from sentinel to run tests in isolated environments.
Each test session gets an ephemeral container with the project mounted from sandbox.
Supports multiple OS/language base images for cross-platform testing.

### Relay Server - Priority: Medium
Relay proxy for NAT traversal when direct gRPC connections fail.
End-to-end encryption through relay (relay sees only ciphertext).

### Web Dashboard - Priority: Low
Web UI for fleet monitoring, session management, and device pairing.
Alternative to CLI for less technical users.

### Auto-Update - Priority: Low
Self-update mechanism for sentinel binary across fleet.
Coordinated rolling updates via fleet controller.

## Tech Debt

_(none yet)_

## Deprecations

_(none yet)_
