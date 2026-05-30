# Pairing, approval & discovery UX — design

**Date:** 2026-05-30
**Status:** approved (chat)

## Goal

Make starting and joining a fleet simple and secure: `serve` initializes itself,
discovery is toggleable from the CLI, joining is one friendly command, and
pairing requires real manual approval.

## Features

### 1. `serve` auto-initializes
`buildDaemon` ensures the CA + admin device identity exist before loading them.
If `ca/ca.crt` or `certs/device.crt` is missing, `ensureIdentity()` runs the same
steps as `ca init` (CA via `ca.LoadOrInit`, sign an admin device cert, write
`device.crt`/`device.key`/`ca.crt`) and logs it. Fresh machine → `sentinel serve`
just works. `ca init` keeps its explicit "already initialized" guard.

### 2. `serve --discovery[=true|false]`
Bool flag. When set (`cmd.Flags().Changed`), it overrides `discovery.enabled`;
otherwise config wins. Applied in `buildDaemon` via a package-level `*bool`.

### 3. `sentinel connect` (new front door)
- `connect <host:7399> [-r role]` → wraps `runBootstrapConnect`.
- `connect --discovery [-r role]` → mDNS scan: 0 → error; 1 → pair; many → list
  addresses and ask for an explicit one.
- On a rejection containing "pending", prints the client's bootstrap device ID and
  `sentinel pair accept <id>` instructions, and exits 0 (pending is expected).

### 4. Real manual approval (the fix)
Today `buildOnPeerAccepted` always returns `true`. New logic:
- `auto_accept: true` → sign (one-step).
- else if `registry.IsTrusted(peerID)` (approved earlier) → sign.
- else → `AddPending` (if new) and **reject** with
  `"pending manual approval — run 'sentinel pair accept <id>' … then reconnect"`.

Approval UI already exists: `pair list`, `pair accept <id>`, `pair reject <id>`.
Client re-runs `connect`; now trusted → cert issued.

## Components touched
- `cmd/serve.go` — `ensureIdentity()` call, `--discovery` flag + override,
  `buildOnPeerAccepted` rewrite.
- `cmd/identity.go` (new) — `ensureIdentity()`.
- `cmd/connect.go` (new) — `connect` command + `discoverServerAddr()`.
- `cmd/root.go` — register `connect`.

## Tests
- `buildOnPeerAccepted`: auto-accept → true; new → (false, pending err) + recorded
  pending; after `Accept` → true. (in-memory sqlite registry)
- `ensureIdentity` idempotent when identity already present.
- `LooksLikeTarget`/discovery selection already covered / network-gated.

## Non-breaking
`bootstrap connect`, `exec`, `pair *` unchanged. `connect` is additive.
