# Phase 3.4 — Crypto Hardening (Design)

**Date:** 2026-06-04
**Status:** Approved (owner sign-off 2026-06-04) — ready for implementation plan
**Spec lineage:** elaborates `docs/superpowers/specs/2026-05-22-hardening-design.md` §Phase 3 workstream 3.4
**Threats closed:** T8.1, T8.2 (CA key compromise), T8.4 (revocation), T2.3 (cert lifetime) — see `docs/security/THREAT-MODEL.md`

---

## 1. Goal & Non-Goals

### Goal

Protect the CA private key at rest, and limit the blast radius of a compromised or stale
device certificate. Concretely: a local attacker who reads `~/.sentinel/ca.key` must not
obtain a usable CA key; a swapped key/cert must be detected; a revoked device must be
rejected at the mTLS handshake; and a leaked device cert must expire on the order of weeks,
not forever.

### Non-Goals (v1 — deferred to backlog)

- HSM / TPM-backed CA key (the OS keystore is the v1 mechanism).
- OCSP responder.
- Distributed CA-signed X.509 CRL (we chose **local** per-node registry revocation; §5).
- Certificate Transparency / external log submission.
- Automatic peer-cert renewal without operator involvement (v1 auto-renews the daemon's
  **own** cert; peer certs surface warnings and reuse the existing `sentinel renew` flow).

---

## 2. Architecture — envelope encryption via an OS keystore

A new package `internal/security/crypto` owns key-at-rest protection. The design is
**envelope encryption**:

1. A per-install random **Data Encryption Key (DEK)** — 32 bytes — is generated once.
2. The CA key file on disk is `AES-256-GCM(DEK, ca.key-PEM)` (authenticated encryption).
3. The **DEK itself** is held by the OS secret store via a `KeyStore` abstraction, never
   written to disk in the clear.

```go
// KeyStore persists a small named secret (the DEK) in an OS-protected store.
type KeyStore interface {
    Get(service, account string) ([]byte, error) // ErrNotFound if absent
    Set(service, account string, secret []byte) error
    Delete(service, account string) error
    Available() bool // true when this backend can be used on the current host
}
```

Backends (platform files, mirroring the `confine` package pattern):

- **Windows** — DPAPI (`CryptProtectData`, user scope) via the `wincred`/Credential Manager,
  or DPAPI-wrapped blob.
- **macOS** — Keychain (`/usr/bin/security` or the Security framework).
- **Linux** — Secret Service / libsecret over D-Bus.

The plan includes a research step to choose a vetted cross-platform keyring library (e.g.
`github.com/zalando/go-keyring`) vs hand-rolled per-OS backends; either way the `KeyStore`
interface is the seam.

### Fallback (headless hosts with no keyring)

When `KeyStore.Available()` is false (typical headless Linux systemd service with no
session keyring), the DEK is instead wrapped with a passphrase:

```
wrapKey = argon2id(passphrase, salt)
storedDEK = AES-256-GCM(wrapKey, DEK)   // written next to ca.key as ca.key.dek
```

The passphrase is read from a configured **env var** or **sealed file** (operator's choice,
§6). The mode is chosen explicitly in config and **logged loudly** at startup so it is never
a silent downgrade.

### Fail-closed

If neither a keystore nor a configured fallback can unwrap the DEK, the daemon **fails to
start with a clear, actionable error** (`internal/clierr`-classified). It MUST NOT silently
regenerate the CA — that would orphan every paired peer (the exact field failure this
hardening campaign began with).

---

## 3. T8.1 + T8.2 — Encrypt + integrity-protect the CA key

T8.1 (confidentiality) and T8.2 (tamper/swap) are **unified by authenticated encryption**:

- **T8.1** — `ca.key` is stored as AES-256-GCM ciphertext; the plaintext EC private key is
  never on disk. The DEK lives in the OS keystore (or passphrase-wrapped fallback).
- **T8.2** — GCM is authenticated: any swap or bit-flip of the ciphertext fails the auth tag
  at decrypt → load fails closed. Additionally, at load, the decrypted key's public key is
  checked to **match `ca.crt`** (catches a swapped *cert*, which is stored `0644`). File mode
  on the encrypted `ca.key` stays `0600`.

The `internal/ca` load/save paths route through `internal/security/crypto`: `writeKeyPEM`
encrypts before write; the loader decrypts and verifies the cert/key match.

---

## 4. Migration — plaintext key → encrypted

On daemon start, `internal/ca` detects whether `ca.key` is plaintext PEM (legacy) or the
new encrypted envelope:

1. Plaintext detected → load it, set up the DEK (keystore or fallback), write the encrypted
   envelope to `ca.key`, and move the original to `ca.key.plaintext.bak` (`0600`) with a loud
   `slog.Warn` instructing the operator to securely delete the backup.
2. Already-encrypted → decrypt normally.
3. The migration is **idempotent** and **fail-closed**: if the DEK can't be established, it
   aborts without destroying the plaintext key.

A `sentinel doctor` check reports whether the CA key is encrypted and whether a
`*.plaintext.bak` lingers.

---

## 5. T8.4 — Local registry revocation

Revocation is per-node, consistent with Sentinel's TOFU per-node trust model (the bootstrap
port is closed post-transition, so a served CRL is the wrong shape here).

- **Schema** — add `revoked INTEGER NOT NULL DEFAULT 0`, `revoked_at TEXT`, `reason TEXT` to
  the fleet registry `Device` row (additive `hasColumn`-guarded migration, same pattern as
  the CA-pin columns).
- **Enforcement** — the mTLS `VerifyPeerCertificate` hook resolves the peer's device ID and
  rejects the handshake (with an `internal/clierr`-classified error) if the device is
  revoked. This is checked alongside the existing CA-pin verification.
- **CLI** — `sentinel revoke <device-id> [--reason <text>]` and `sentinel unrevoke
  <device-id>`; `sentinel fleet list` shows revoked status.
- **Audit** — the revoke/unrevoke actions emit `device.revoked` / `device.unrevoked`
  (critical); a handshake rejected because the peer is revoked emits the existing
  `pairing.reject` event with `Detail{reason: "revoked"}` (no new event type needed for the
  rejection path).

Revocation takes effect immediately for **new** handshakes; existing live connections from a
now-revoked peer are closed on their next session heartbeat check.

---

## 6. T2.3 — Short-lived certs + auto-renewal

- **Validity** — new device certs are issued with `CertValidity` (default **720h / 30d**,
  configurable up to a hard max). Existing long-lived certs keep working until they expire
  (no forced break).
- **Auto-renewal (own cert)** — a daemon goroutine checks its own cert and, when remaining
  life drops below `RenewThreshold` (default **240h / 10d**, i.e. ⅓ of a 30d cert), the local
  CA **re-signs** the daemon's own cert in place (the node owns its CA — no peer interaction
  needed). Emits `cert.autorenew` (routine).
- **Peer certs** — when a paired peer's cert nears expiry, the daemon logs a warning and the
  operator uses the existing time-boxed `sentinel renew` window to re-exchange. (Fully
  automatic peer renewal is a backlog item.)
- The existing `warnCertExpiry` startup check is extended to drive both paths.

---

## 7. Config — `crypto` block (schema v4 → v5)

```go
type CryptoConfig struct {
    KeyEncryption  string        // "keystore" (default) | "passphrase-env" | "passphrase-file" | "off"
    PassphraseEnv  string        // env var name when KeyEncryption=passphrase-env (default SENTINEL_CA_PASSPHRASE)
    PassphraseFile string        // path when KeyEncryption=passphrase-file
    CertValidity   time.Duration // default 720h (30d)
    RenewThreshold time.Duration // default 240h (10d); auto-renew own cert under this
}
```

`Validate`: `KeyEncryption` is one of the four values; `passphrase-env`/`passphrase-file`
require the corresponding field; `CertValidity > 0` and `<= maxCertValidity` (e.g. 90d);
`0 < RenewThreshold < CertValidity`. `"off"` is allowed but logs a prominent warning (key
stored plaintext — for dev only). `Migrate` adds v5 defaults to v4 configs.

---

## 8. Audit & Doctor Integration

- **Audit catalog** (Phase 3.1): `device.revoked` (critical), `device.unrevoked` (critical),
  `cakey.sealed` (critical — first encryption/migration), `cakey.unseal_failed` (critical),
  `cert.autorenew` (routine). The registry-completeness test forces classification.
- **Doctor**: a `checkCAKeyAtRest` check — reports encrypted vs plaintext, keystore vs
  fallback mode, and a lingering `*.plaintext.bak`.

---

## 9. Testing Strategy (TDD)

Table-driven, with a **fake `KeyStore`** (in-memory) so the crypto path is testable without
a real OS keyring:

1. **Envelope round-trip** — encrypt then decrypt `ca.key` via a fake keystore returns the
   original key.
2. **Tamper detection** — flip a byte of the ciphertext → decrypt fails (GCM auth); swap the
   cert → cert/key-match check fails.
3. **Fallback** — passphrase-env and passphrase-file modes round-trip; wrong passphrase fails.
4. **Fail-closed** — no keystore + no fallback → daemon load returns a classified error and
   does NOT regenerate the CA.
5. **Migration** — a plaintext `ca.key` is encrypted in place, `.plaintext.bak` created,
   second start is a no-op (idempotent); aborting mid-migration leaves the plaintext intact.
6. **Revocation** — a revoked device's handshake is rejected; `unrevoke` restores; migration
   adds the columns to a pre-existing DB.
7. **Short-lived cert** — issued cert `NotAfter-NotBefore == CertValidity`; auto-renew fires
   when remaining < `RenewThreshold` and produces a fresh cert; does not fire above it.
8. **Config** — v4→v5 migration; `Validate` rejects bad modes/durations.

Platform: the keystore backends are platform-tagged; CI compiles all via `GOOS` matrix, and
unit tests use the fake keystore. A real-keystore smoke test is `//go:build` + skipped in CI.

---

## 10. Architecture Impact & Risk

- **Biggest risk — locking out the CA.** If the keystore behaves differently across
  restart/upgrade (e.g. a Windows user-profile change, a re-keyed keyring), the daemon could
  fail to unseal its own CA. Mitigations: the `.plaintext.bak` on first migration (operator
  recovery), a `sentinel ca export`-style escape hatch documented, the explicit fallback
  mode, and **never** auto-regenerating. The plan's research step must validate keystore
  persistence across restart on each platform before wiring it as the default.
- **Headless Linux** — Secret Service is frequently absent on servers; the passphrase-env
  fallback is the realistic default there, and the docs must say so.
- **Interaction with Phase 3.1/3.x** — revocation reuses the fleet registry + the audit
  logger (already wired); auto-renewal extends the existing `warnCertExpiry`/`sentinel renew`
  machinery; no new transport surface.
- **Backward compatibility** — existing installs migrate transparently on first start;
  existing long-lived certs are honored until expiry; the only operator action is deleting the
  `.plaintext.bak`.

---

## 11. Deliverables Checklist

- [ ] `internal/security/crypto`: `KeyStore` interface + platform backends + fake; envelope
      AES-256-GCM encrypt/decrypt; passphrase (argon2id) fallback.
- [ ] `internal/ca` load/save routed through the envelope; cert/key match check; fail-closed.
- [ ] Plaintext→encrypted migration with `.plaintext.bak` + idempotency.
- [ ] Fleet registry `revoked`/`revoked_at`/`reason` columns + additive migration.
- [ ] mTLS `VerifyPeerCertificate` rejects revoked devices; live-connection close on heartbeat.
- [ ] `sentinel revoke` / `sentinel unrevoke`; `fleet list` shows revoked.
- [ ] Short-lived cert issuance (`CertValidity`) + own-cert auto-renewal (`RenewThreshold`).
- [ ] `CryptoConfig` settings block + v4→v5 migration.
- [ ] Audit events (`device.revoked`, `cakey.sealed`, `cert.autorenew`, …) + doctor check.
- [ ] Full TDD suite (§9); `go build`/`vet`/`test`/`golangci-lint` green; linux cross-build;
      threat-model T8.1/T8.2/T8.4/T2.3 → mitigated + `HARDENING-STATUS.md` Phase 3.4 entry.
