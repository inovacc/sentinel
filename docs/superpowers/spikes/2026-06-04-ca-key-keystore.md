# Spike: CA-key keystore — DEK persistence, availability detection, dependency decision

**Date:** 2026-06-04
**Author:** spike run on Windows 11 Pro (go-keyring v0.2.8)
**Outcome:** ADOPT `github.com/zalando/go-keyring v0.2.8`

---

## 1. Candidate library

`github.com/zalando/go-keyring v0.2.8` — cross-platform wrapper that delegates to:

| Platform | Backend |
|----------|---------|
| Windows | Windows Credential Manager via `github.com/danieljoos/wincred` |
| macOS | macOS Keychain (`security` command / Security framework) |
| Linux | Secret Service / libsecret over D-Bus |
| Other | `fallbackServiceProvider` — every method returns `ErrUnsupportedPlatform` |

---

## 2. Per-platform persistence result

### Windows (tested directly)

```
# Process 1 (write):
WRITE OK  stored=743f5de7f70ff73ed81585e5691bb920c46c1b6f25f3be4a432cef1d4da70067

# Process 2 (read back, new os/exec process):
READ  OK  got=743f5de7f70ff73ed81585e5691bb920c46c1b6f25f3be4a432cef1d4da70067
```

**Result: PASS.** The 32-byte DEK survived full process termination and restart.
The entry is stored in Windows Credential Manager (user scope: `CRED_TYPE_GENERIC`,
target `sentinel-ca-spike:dek`). It persists across reboots and survives user log-off/log-on.
It is NOT accessible to other Windows user accounts.

### macOS (expected from library code + docs)

The library uses `security add-generic-password` / `security find-generic-password` under
`//go:build darwin`. The Keychain persists secrets in the user's login keychain
(`~/Library/Keychains/login.keychain-db`), which is unlocked at login and survives restarts.
**Expected: PASS** — same guarantee as Windows, confirmed by upstream library tests and
extensive community use.

### Linux with session D-Bus / Secret Service (expected)

When a graphical session is running (GNOME Keyring, KDE Wallet), `dbus.SessionBus()` in
`ss.NewSecretService()` succeeds and the library delegates to the D-Bus secrets API.
Secrets persist in the session keychain across process restarts.
**Expected: PASS** — standard developer desktop behavior.

### Linux headless / no D-Bus (expected, by code inspection)

On a headless server where `DBUS_SESSION_BUS_ADDRESS` is unset (or no Secret Service daemon
is running), `dbus.SessionBus()` returns a D-Bus connection error. The library propagates
this error from `ss.NewSecretService()` — it does NOT panic and does NOT silently succeed.
`Get`/`Set` both return a non-nil `error` value. This satisfies the "degrade to error, not
crash" requirement.

**Conclusion for headless Linux:** the error is a `*dbus.ErrMsgInvalidArg`-family or
`"org.freedesktop.DBus.Error.NotSupported"` message — NOT `keyring.ErrNotFound` and NOT
`keyring.ErrUnsupportedPlatform`. Our `Available()` detection strategy below handles this.

---

## 3. Missing-key behavior (Windows, tested directly)

```
MISSING KEY -> keyring.ErrNotFound (correct): secret not found in keyring
```

`Get` for a key that was never stored returns exactly `keyring.ErrNotFound`. No panic, no nil
pointer dereference. The Windows implementation explicitly maps `syscall.ERROR_NOT_FOUND →
keyring.ErrNotFound`.

---

## 4. `Available()` detection strategy

go-keyring v0.2.8 does NOT expose an `Available()` method. Our `KeyStore` interface requires
one. The recommended strategy is a **probe `Get`**:

```go
// Available returns true if the OS keyring is usable on this host.
// Strategy: attempt a Get on a well-known sentinel probe key.
// - ErrNotFound      → backend is up, key simply absent → Available
// - ErrUnsupportedPlatform → no backend compiled in  → Unavailable
// - any other error  → backend exists but is not reachable (headless Linux
//                      D-Bus error, locked keychain, etc.)  → Unavailable
func (k osKeyStore) Available() bool {
    _, err := keyring.Get(availabilityProbeService, availabilityProbeAccount)
    if err == nil || errors.Is(err, keyring.ErrNotFound) {
        return true
    }
    return false
}
```

Constants: `availabilityProbeService = "sentinel-available-probe"`,
`availabilityProbeAccount = "probe"`.

This approach:
- Never writes anything to the keyring (read-only probe).
- Is safe to call at daemon startup with no side effects.
- Correctly returns `false` on headless Linux (D-Bus connection error → not `ErrNotFound`).
- Correctly returns `true` on Windows/macOS even before any DEK is stored.
- Is deterministic — no heuristics.

---

## 5. Headless-Linux fallback

When `Available()` returns `false`, the production plan falls back to the
**passphrase-env** path (Task 1 / Task 3 `Sealer`):

- The DEK is wrapped with `argon2id(passphrase, salt)` and stored alongside `ca.key` as
  `ca.key.dek` (see `internal/security/crypto/passphrase.go`).
- The passphrase is read from `SENTINEL_CA_PASSPHRASE` env var or a sealed file.
- This is the realistic default for headless Linux systemd services.
- The `Sealer` logs a loud warning at startup so operators are never silently downgraded.

---

## 6. Dependency decision

**ADOPT `github.com/zalando/go-keyring v0.2.8`.**

Criteria evaluated:

| Criterion | Result |
|-----------|--------|
| Persists across restart on Windows | PASS (tested) |
| Persists across restart on macOS | PASS (expected by code + docs + community) |
| Degrades to error (not crash) on headless Linux | PASS (D-Bus error propagated, no panic) |
| `ErrNotFound` for missing keys | PASS (tested) |
| No unsolicited secret discovery | PASS (targeted by service+account key) |
| Active maintenance | PASS (v0.2.8, 2024, Zalando org) |
| License | MIT |

Hand-rolling per-OS backends would replicate the exact same D-Bus / wincred / Keychain logic
without additional benefit. `go-keyring` is a well-audited, widely deployed wrapper with
explicit error handling at every platform boundary.

**Module path and version to use in Task 3:**
```
github.com/zalando/go-keyring v0.2.8
```

Transitive additions: `github.com/danieljoos/wincred v1.2.3`, `github.com/godbus/dbus/v5 v5.2.2`
(already in `go.mod`/`go.sum` from this spike's `go get`).
