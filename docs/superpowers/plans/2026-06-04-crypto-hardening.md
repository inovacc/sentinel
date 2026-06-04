# Phase 3.4 — Crypto Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Protect the CA private key at rest with envelope AES-256-GCM (DEK in an OS keystore, argon2id passphrase fallback, fail-closed — never regenerate), detect a swapped cert/key, revoke devices locally (per-node registry), and shorten device-cert lifetime with own-cert auto-renewal. Closes threats T8.1, T8.2 (CA key compromise), T8.4 (revocation), T2.3 (cert lifetime).

**Architecture:** A new `internal/security/crypto` package owns key-at-rest protection via a `KeyStore` seam (platform backends mirroring `internal/confine`, plus an in-memory fake for tests and a `Decide`-style selector that falls back to passphrase when no keystore is available). `internal/ca` Load/Save route through the envelope and verify the decrypted key's public half matches `ca.crt`. The fleet registry gains additive `revoked`/`revoked_at`/`reason` columns; the mTLS server's `VerifyPeerCertificate` hook rejects revoked peers; a session-heartbeat sweep closes live revoked connections. `CryptoConfig` (schema v4→v5) holds the knobs. Short-lived certs + an own-cert auto-renew goroutine extend the existing `warnCertExpiry` machinery. New audit events and a `doctor` check complete the wiring.

**Tech Stack:** Go 1.26 (`github.com/inovacc/sentinel`), `crypto/aes`+`crypto/cipher` (GCM), `golang.org/x/crypto/argon2` (new dep), an OS-keyring dep chosen in Task 2 (candidate `github.com/zalando/go-keyring`), `modernc.org/sqlite`, Cobra, `log/slog`. Table-driven tests; `t.TempDir()` for key/DB files; the fake `KeyStore` for all crypto unit tests (no real OS keyring in CI); platform-tagged real-keystore smoke test skipped in CI. Cross-platform compile-verify: `$env:GOOS='linux'; go vet ./...; $env:GOOS=''`.

---

## File Structure

### Created

| File | Responsibility |
|------|----------------|
| `internal/security/crypto/keystore.go` | `KeyStore` interface, `ErrNotFound`, the `Select`/`Decide` mode-picker, and `KeyEncryption*` mode constants. |
| `internal/security/crypto/keystore_fake.go` | In-memory `FakeKeyStore` (testable everywhere; `Available()` toggleable). Build-tagged `//go:build !prod` is NOT used — it is plain Go so tests in any package can use it. |
| `internal/security/crypto/envelope.go` | `Encrypt`/`Decrypt` (AES-256-GCM) over a 32-byte DEK; DEK generation; the on-disk envelope framing (magic + version + nonce + ciphertext). |
| `internal/security/crypto/passphrase.go` | argon2id passphrase→wrapKey derivation; `WrapDEK`/`UnwrapDEK`; the `ca.key.dek` wrapped-DEK file format (salt + params + wrapped DEK). |
| `internal/security/crypto/manager.go` | `Sealer`: ties a `KeyStore` + config together; `Seal(plaintext) ([]byte, error)` / `Unseal(ciphertext) ([]byte, error)`; establishes/loads the DEK (keystore or passphrase) fail-closed. |
| `internal/security/crypto/keystore_windows.go` | `//go:build windows` DPAPI/Credential-Manager backend + `Available()`. |
| `internal/security/crypto/keystore_darwin.go` | `//go:build darwin` Keychain backend + `Available()`. |
| `internal/security/crypto/keystore_linux.go` | `//go:build linux` Secret Service backend + `Available()`. |
| `internal/security/crypto/keystore_other.go` | `//go:build !windows && !linux && !darwin` no-op backend (`Available()==false`). |
| `internal/security/crypto/keystore_real_test.go` | `//go:build keystore_smoke` real-keystore round-trip + persistence smoke test, skipped in CI. |
| `internal/security/crypto/envelope_test.go` | Round-trip, tamper, wrong-DEK tests (fake keystore). |
| `internal/security/crypto/passphrase_test.go` | argon2id wrap/unwrap, wrong-passphrase tests. |
| `internal/security/crypto/manager_test.go` | Seal/Unseal via fake; fail-closed (no keystore + no passphrase); mode selection. |
| `internal/ca/sealedkey.go` | `writeKeyPEMSealed`/`loadKeyPEMSealed` and `isEncryptedKey`; plaintext→encrypted migration helper. |
| `internal/ca/sealedkey_test.go` | Migration idempotency, `.plaintext.bak`, abort-leaves-plaintext, cert/key-match. |
| `cmd/revoke.go` | `sentinel revoke` / `sentinel unrevoke` Cobra commands. |
| `cmd/revoke_test.go` | CLI round-trip against a temp registry. |
| `docs/superpowers/spikes/2026-06-04-ca-key-keystore.md` | Keystore research findings (Task 2). |

### Modified

| File | Change |
|------|--------|
| `internal/ca/ca.go` | Route `Init`/`Load`/`SignDevice` through the sealer; configurable cert validity (`SignDeviceFor`); add `ReSignSelf` for auto-renew; public-key cert/key match check at load. |
| `internal/fleet/registry.go` | Additive `revoked`/`revoked_at`/`reason` columns; extend `Device`, SELECT lists, scan funcs; add `Revoke`/`Unrevoke`/`IsRevoked`; audit emission. |
| `pkg/transport/mtls.go` | `MTLSConfig.VerifyPeer` hook field; `NewMTLSServerConfig` wires it into `VerifyPeerCertificate`. |
| `internal/settings/settings.go` | `CryptoConfig` block; `defaultCryptoConfig()`; wire into `Config`, `DefaultConfig`, `Validate`, `Migrate`; bump `CurrentConfigVersion` 4→5. |
| `internal/audit/catalog.go` | Add `device.revoked`, `device.unrevoked`, `cakey.sealed`, `cakey.unseal_failed` (Critical) and `cert.autorenew` (Routine). |
| `internal/clierr/clierr.go` | Add `KindCAUnseal`; classify CA-unseal failure into actionable remediation. |
| `cmd/serve.go` | Build sealer from config; pass revocation-checking `VerifyPeer` into the mTLS server config; own-cert auto-renew goroutine; revoked-connection sweep; emit `cakey.sealed`. |
| `cmd/fleet.go` | `fleet list` shows revoked status (JSON already carries it via `Device`). |
| `cmd/doctor.go` | Add `checkCAKeyAtRest` and append it in `runDoctor`. |
| `docs/security/THREAT-MODEL.md` | Mark T8.1/T8.2/T8.4/T2.3 mitigated. |
| `docs/superpowers/HARDENING-STATUS.md` | Add the Phase 3.4 entry. |
| `go.mod` / `go.sum` | Add `golang.org/x/crypto` and the chosen keyring dep. |

---

## Task 1 — `internal/security/crypto`: KeyStore seam, fake, envelope, passphrase fallback

Pure, fully unit-testable with the fake. No OS keyring touched. Do this first.

### 1a. KeyStore interface + fake + mode constants

- [ ] Write `internal/security/crypto/keystore.go`:

```go
// Package crypto provides envelope encryption for the CA private key at rest.
// A per-install Data Encryption Key (DEK) encrypts the key with AES-256-GCM; the
// DEK itself is held by an OS KeyStore, or — on hosts without one — wrapped with
// an argon2id-derived key from an operator passphrase. The design fails closed:
// if the DEK cannot be established, callers must refuse rather than regenerate.
package crypto

import "errors"

// ErrNotFound is returned by KeyStore.Get when the named secret is absent.
var ErrNotFound = errors.New("crypto: secret not found in keystore")

// KeyStore persists a small named secret (the DEK) in an OS-protected store.
type KeyStore interface {
	// Get returns the secret for (service, account), or ErrNotFound if absent.
	Get(service, account string) ([]byte, error)
	// Set stores secret for (service, account), overwriting any existing value.
	Set(service, account string, secret []byte) error
	// Delete removes the secret for (service, account). Absent is not an error.
	Delete(service, account string) error
	// Available reports whether this backend can be used on the current host.
	Available() bool
}

// KeyEncryption modes mirror settings.CryptoConfig.KeyEncryption.
const (
	ModeKeystore      = "keystore"
	ModePassphraseEnv = "passphrase-env"
	ModePassphraseFile = "passphrase-file"
	ModeOff           = "off"
)

// The default service/account names under which the DEK is stored.
const (
	keystoreService = "sentinel-ca"
	keystoreAccount = "dek"
)
```

- [ ] Write `internal/security/crypto/keystore_fake.go`:

```go
package crypto

import "sync"

// FakeKeyStore is an in-memory KeyStore for tests. It is plain Go (not build-
// tagged) so any package's tests can use it. available controls Available().
type FakeKeyStore struct {
	mu        sync.Mutex
	data      map[string][]byte
	available bool
}

// NewFakeKeyStore returns an available, empty fake.
func NewFakeKeyStore() *FakeKeyStore {
	return &FakeKeyStore{data: map[string][]byte{}, available: true}
}

// SetAvailable toggles what Available() reports (to exercise the fallback path).
func (f *FakeKeyStore) SetAvailable(v bool) { f.mu.Lock(); f.available = v; f.mu.Unlock() }

func (f *FakeKeyStore) key(service, account string) string { return service + "\x00" + account }

func (f *FakeKeyStore) Get(service, account string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.data[f.key(service, account)]
	if !ok {
		return nil, ErrNotFound
	}
	out := make([]byte, len(v))
	copy(out, v)
	return out, nil
}

func (f *FakeKeyStore) Set(service, account string, secret []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]byte, len(secret))
	copy(cp, secret)
	f.data[f.key(service, account)] = cp
	return nil
}

func (f *FakeKeyStore) Delete(service, account string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.data, f.key(service, account))
	return nil
}

func (f *FakeKeyStore) Available() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.available
}
```

- [ ] Run `go build ./internal/security/crypto/`. Expect PASS (no tests yet; verifies it compiles).
- [ ] Commit:
  - `git add internal/security/crypto/keystore.go internal/security/crypto/keystore_fake.go`
  - `git commit -m "feat(crypto): add KeyStore interface and in-memory fake"`

### 1b. Envelope AES-256-GCM (failing test first)

- [ ] Write `internal/security/crypto/envelope_test.go`:

```go
package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	dek := mustDEK(t)
	plaintext := []byte("-----BEGIN EC PRIVATE KEY-----\nfake\n-----END EC PRIVATE KEY-----\n")

	ct, err := Encrypt(dek, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Contains(ct, plaintext) {
		t.Fatal("ciphertext contains plaintext")
	}

	got, err := Decrypt(dek, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, plaintext)
	}
}

func TestDecryptTamperedFails(t *testing.T) {
	dek := mustDEK(t)
	ct, err := Encrypt(dek, []byte("secret-key-material"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ct[len(ct)-1] ^= 0xFF // flip a ciphertext byte
	if _, err := Decrypt(dek, ct); err == nil {
		t.Fatal("expected auth failure on tampered ciphertext, got nil")
	}
}

func TestDecryptWrongKeyFails(t *testing.T) {
	ct, err := Encrypt(mustDEK(t), []byte("secret-key-material"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := Decrypt(mustDEK(t), ct); err == nil {
		t.Fatal("expected failure decrypting with a different DEK")
	}
}

func TestEncryptRejectsBadDEKLength(t *testing.T) {
	if _, err := Encrypt(make([]byte, 16), []byte("x")); err == nil {
		t.Fatal("expected error for 16-byte DEK (must be 32)")
	}
}

func mustDEK(t *testing.T) []byte {
	t.Helper()
	dek, err := NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	if len(dek) != DEKSize {
		t.Fatalf("DEK size = %d, want %d", len(dek), DEKSize)
	}
	return dek
}
```

- [ ] Run `go test ./internal/security/crypto/ -run TestEncrypt -run TestDecrypt`. Expect FAIL: `undefined: Encrypt` / `undefined: NewDEK` / `undefined: DEKSize`.
- [ ] Write `internal/security/crypto/envelope.go`:

```go
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// DEKSize is the Data Encryption Key length in bytes (AES-256).
const DEKSize = 32

// envelopeMagic and envelopeVersion frame the on-disk ciphertext so a plaintext
// PEM (which never starts with these bytes) is distinguishable from an envelope.
var envelopeMagic = []byte("SENTCAK1") // Sentinel CA Key, format 1

// NewDEK generates a fresh 32-byte random Data Encryption Key.
func NewDEK() ([]byte, error) {
	dek := make([]byte, DEKSize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("crypto: generate DEK: %w", err)
	}
	return dek, nil
}

// Encrypt seals plaintext with AES-256-GCM under dek. The output is
// magic || nonce || ciphertext(+tag). dek MUST be DEKSize bytes.
func Encrypt(dek, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("crypto: nonce: %w", err)
	}
	out := make([]byte, 0, len(envelopeMagic)+len(nonce)+len(plaintext)+gcm.Overhead())
	out = append(out, envelopeMagic...)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plaintext, envelopeMagic), nil
}

// Decrypt opens an envelope produced by Encrypt. It fails on any tamper (GCM
// auth) or framing error.
func Decrypt(dek, envelope []byte) ([]byte, error) {
	gcm, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	if !IsEnvelope(envelope) {
		return nil, fmt.Errorf("crypto: not a sentinel key envelope")
	}
	body := envelope[len(envelopeMagic):]
	ns := gcm.NonceSize()
	if len(body) < ns {
		return nil, fmt.Errorf("crypto: envelope truncated")
	}
	nonce, ct := body[:ns], body[ns:]
	pt, err := gcm.Open(nil, nonce, ct, envelopeMagic)
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt (auth failed — tampered or wrong key): %w", err)
	}
	return pt, nil
}

// IsEnvelope reports whether data begins with the envelope magic (i.e. is an
// encrypted key, not a plaintext PEM).
func IsEnvelope(data []byte) bool {
	if len(data) < len(envelopeMagic) {
		return false
	}
	for i := range envelopeMagic {
		if data[i] != envelopeMagic[i] {
			return false
		}
	}
	return true
}

func newGCM(dek []byte) (cipher.AEAD, error) {
	if len(dek) != DEKSize {
		return nil, fmt.Errorf("crypto: DEK must be %d bytes, got %d", DEKSize, len(dek))
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("crypto: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: gcm: %w", err)
	}
	return gcm, nil
}
```

- [ ] Run `go test ./internal/security/crypto/`. Expect PASS.
- [ ] Commit:
  - `git add internal/security/crypto/envelope.go internal/security/crypto/envelope_test.go`
  - `git commit -m "feat(crypto): envelope AES-256-GCM encrypt/decrypt for the CA key"`

### 1c. argon2id passphrase fallback (failing test first)

- [ ] Add the dependency: `go get golang.org/x/crypto/argon2`.
- [ ] Write `internal/security/crypto/passphrase_test.go`:

```go
package crypto

import (
	"bytes"
	"testing"
)

func TestWrapUnwrapDEKRoundTrip(t *testing.T) {
	dek := mustDEK(t)
	wrapped, err := WrapDEK([]byte("correct horse battery staple"), dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	if bytes.Contains(wrapped, dek) {
		t.Fatal("wrapped blob leaks the DEK")
	}
	got, err := UnwrapDEK([]byte("correct horse battery staple"), wrapped)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("unwrapped DEK mismatch")
	}
}

func TestUnwrapWrongPassphraseFails(t *testing.T) {
	wrapped, err := WrapDEK([]byte("right"), mustDEK(t))
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	if _, err := UnwrapDEK([]byte("wrong"), wrapped); err == nil {
		t.Fatal("expected failure unwrapping with wrong passphrase")
	}
}

func TestWrapRejectsEmptyPassphrase(t *testing.T) {
	if _, err := WrapDEK(nil, mustDEK(t)); err == nil {
		t.Fatal("expected error for empty passphrase")
	}
}
```

- [ ] Run `go test ./internal/security/crypto/ -run TestWrap -run TestUnwrap`. Expect FAIL: `undefined: WrapDEK`.
- [ ] Write `internal/security/crypto/passphrase.go`:

```go
package crypto

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// argon2id parameters. These are conservative interactive defaults; the salt is
// stored alongside the wrapped DEK so they need not be configurable for v1.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 4
	argonSalt    = 16
)

var wrapMagic = []byte("SENTDEK1") // Sentinel wrapped-DEK, format 1

// WrapDEK derives a 32-byte key from passphrase via argon2id and uses it to
// AES-256-GCM-encrypt dek. Output: wrapMagic || salt || envelope(wrapKey, dek).
func WrapDEK(passphrase, dek []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("crypto: empty passphrase")
	}
	salt := make([]byte, argonSalt)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("crypto: salt: %w", err)
	}
	wrapKey := argon2.IDKey(passphrase, salt, argonTime, argonMemory, argonThreads, DEKSize)
	sealed, err := Encrypt(wrapKey, dek)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(wrapMagic)+len(salt)+len(sealed))
	out = append(out, wrapMagic...)
	out = append(out, salt...)
	return append(out, sealed...), nil
}

// UnwrapDEK reverses WrapDEK. Wrong passphrase fails the GCM auth tag.
func UnwrapDEK(passphrase, wrapped []byte) ([]byte, error) {
	if len(wrapped) < len(wrapMagic)+argonSalt {
		return nil, fmt.Errorf("crypto: wrapped DEK truncated")
	}
	for i := range wrapMagic {
		if wrapped[i] != wrapMagic[i] {
			return nil, fmt.Errorf("crypto: not a wrapped DEK blob")
		}
	}
	rest := wrapped[len(wrapMagic):]
	salt, sealed := rest[:argonSalt], rest[argonSalt:]
	wrapKey := argon2.IDKey(passphrase, salt, argonTime, argonMemory, argonThreads, DEKSize)
	dek, err := Decrypt(wrapKey, sealed)
	if err != nil {
		return nil, fmt.Errorf("crypto: unwrap DEK (wrong passphrase?): %w", err)
	}
	return dek, nil
}
```

- [ ] Run `go test ./internal/security/crypto/`. Expect PASS.
- [ ] Commit:
  - `git add internal/security/crypto/passphrase.go internal/security/crypto/passphrase_test.go go.mod go.sum`
  - `git commit -m "feat(crypto): argon2id passphrase fallback for DEK wrapping"`

---

## Task 2 — Keystore spike: validate cross-restart persistence, decide the dependency

A research/spike task (like the DoS trampoline spike). NO production wiring here — the deliverable is a findings doc and a dependency decision.

- [ ] Create a throwaway `spike/keystore/main.go` (outside the build — delete after) that, for the candidate `github.com/zalando/go-keyring`:
  1. `Set("sentinel-ca-spike", "dek", <random 32 bytes>)`, prints the value.
  2. In a SECOND process invocation (`go run ./spike/keystore --read`), `Get` the same key and confirm it returns the identical bytes — proving persistence across process restart.
  3. Probe `Available()` semantics: on Linux without a Secret Service (`unset DBUS_SESSION_BUS_ADDRESS`), confirm `Get`/`Set` return an error rather than panicking, so a wrapper `Available()` can detect headlessness.
- [ ] Run the spike on each reachable platform (at minimum Windows here; document Linux/macOS expectations from the library's behavior + docs). Use `ctx_execute` for any long output.
- [ ] Decide: adopt `github.com/zalando/go-keyring` IF it (a) persists across restart on Windows + macOS, (b) degrades to an error (not a crash) on headless Linux. Otherwise fall back to hand-rolled per-OS backends. Record the decision and rationale.
- [ ] Write `docs/superpowers/spikes/2026-06-04-ca-key-keystore.md` capturing: per-platform persistence result, the `Available()` detection strategy (try a benign `Get` of a probe key and treat a backend/D-Bus error as unavailable), the headless-Linux fallback (passphrase-env is the realistic server default), and the final dependency decision with the module path + version.
- [ ] Remove the throwaway spike dir: `rm -rf spike/keystore`.
- [ ] If adopting the dep: `go get github.com/zalando/go-keyring@<version>`.
- [ ] Commit:
  - `git add docs/superpowers/spikes/2026-06-04-ca-key-keystore.md go.mod go.sum`
  - `git commit -m "spike(crypto): validate keystore DEK persistence, choose keyring dep"`

> **For the remaining tasks, "the keyring library" means the dependency chosen here.** If the spike rejected `go-keyring`, the platform backends in Task 3 implement DPAPI / Keychain / Secret-Service directly behind the same `KeyStore` interface; the `Sealer` and all callers are unchanged because the interface is the seam.

---

## Task 3 — Platform KeyStore backends + the mode selector (`Sealer`)

### 3a. Platform backends

- [ ] Write `internal/security/crypto/keystore_windows.go` (assumes the chosen keyring lib; adapt the body if hand-rolling):

```go
//go:build windows

package crypto

import (
	"errors"

	"github.com/zalando/go-keyring"
)

type osKeyStore struct{}

func newOSKeyStore() KeyStore { return osKeyStore{} }

func (osKeyStore) Get(service, account string) ([]byte, error) {
	v, err := keyring.Get(service, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return []byte(v), nil
}

func (osKeyStore) Set(service, account string, secret []byte) error {
	return keyring.Set(service, account, string(secret))
}

func (osKeyStore) Delete(service, account string) error {
	if err := keyring.Delete(service, account); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return err
	}
	return nil
}

// Available probes the Credential Manager with a benign round-trip. DPAPI/CredMan
// is always present on Windows desktops/servers, but we still verify rather than
// assume so a locked-down host downgrades to the passphrase fallback cleanly.
func (osKeyStore) Available() bool { return probeKeystore(osKeyStore{}) }
```

- [ ] Write `internal/security/crypto/keystore_darwin.go` and `internal/security/crypto/keystore_linux.go` identically (same `osKeyStore` body, `//go:build darwin` / `//go:build linux`) since the keyring lib abstracts the backend. (If hand-rolling, each file calls its OS API.) Add the shared probe in `keystore.go`:

```go
// probeKeystore reports whether a backend round-trips a benign probe secret. A
// backend/D-Bus/CredMan error means unavailable (e.g. headless Linux with no
// Secret Service) → caller falls back to the passphrase mode.
func probeKeystore(ks KeyStore) bool {
	const probeAcct = "availability-probe"
	if err := ks.Set(keystoreService, probeAcct, []byte("1")); err != nil {
		return false
	}
	_ = ks.Delete(keystoreService, probeAcct)
	return true
}
```

- [ ] Write `internal/security/crypto/keystore_other.go`:

```go
//go:build !windows && !linux && !darwin

package crypto

type osKeyStore struct{}

func newOSKeyStore() KeyStore               { return osKeyStore{} }
func (osKeyStore) Get(string, string) ([]byte, error) { return nil, ErrNotFound }
func (osKeyStore) Set(string, string, []byte) error   { return ErrNotFound }
func (osKeyStore) Delete(string, string) error        { return nil }
func (osKeyStore) Available() bool                     { return false }
```

### 3b. Mode selector + Sealer (failing test first)

- [ ] Write `internal/security/crypto/manager_test.go`:

```go
package crypto

import (
	"bytes"
	"testing"
)

func TestSealUnsealKeystoreMode(t *testing.T) {
	ks := NewFakeKeyStore()
	s, err := NewSealer(Options{Mode: ModeKeystore, KeyStore: ks})
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	key := []byte("ca-private-key-pem")
	sealed, err := s.Seal(key)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// A second Sealer reusing the same keystore must Unseal (DEK persisted).
	s2, err := NewSealer(Options{Mode: ModeKeystore, KeyStore: ks})
	if err != nil {
		t.Fatalf("NewSealer 2: %v", err)
	}
	got, err := s2.Unseal(sealed)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("unseal mismatch")
	}
}

func TestSealPassphraseModeRoundTrip(t *testing.T) {
	var dekFile []byte
	opts := Options{
		Mode:       ModePassphraseEnv,
		Passphrase: []byte("hunter2"),
		LoadDEKFile: func() ([]byte, error) { return dekFile, nil },
		SaveDEKFile: func(b []byte) error { dekFile = b; return nil },
	}
	s, err := NewSealer(opts)
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	sealed, err := s.Seal([]byte("k"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	s2, _ := NewSealer(opts) // reloads the wrapped DEK from dekFile
	if _, err := s2.Unseal(sealed); err != nil {
		t.Fatalf("Unseal after reload: %v", err)
	}
}

func TestSealerFailsClosedNoKeystoreNoPassphrase(t *testing.T) {
	ks := NewFakeKeyStore()
	ks.SetAvailable(false)
	_, err := NewSealer(Options{Mode: ModeKeystore, KeyStore: ks})
	if err == nil {
		t.Fatal("expected fail-closed error when keystore unavailable and no fallback")
	}
}

func TestSealerOffModeIsPassthrough(t *testing.T) {
	s, err := NewSealer(Options{Mode: ModeOff})
	if err != nil {
		t.Fatalf("NewSealer off: %v", err)
	}
	sealed, _ := s.Seal([]byte("plain"))
	if !bytes.Equal(sealed, []byte("plain")) {
		t.Fatal("off mode must pass plaintext through unchanged")
	}
}
```

- [ ] Run `go test ./internal/security/crypto/ -run TestSeal`. Expect FAIL: `undefined: NewSealer`.
- [ ] Write `internal/security/crypto/manager.go`:

```go
package crypto

import (
	"errors"
	"fmt"
)

// Options configures a Sealer. Exactly one DEK source is established:
//   - ModeKeystore: DEK lives in KeyStore (created on first Seal).
//   - ModePassphraseEnv / ModePassphraseFile: DEK is wrapped by Passphrase and
//     persisted via SaveDEKFile / read via LoadDEKFile (the ca.key.dek file).
//   - ModeOff: no encryption (Seal/Unseal are identity) — dev only.
type Options struct {
	Mode        string
	KeyStore    KeyStore // required for ModeKeystore
	Passphrase  []byte   // required for passphrase modes
	LoadDEKFile func() ([]byte, error)   // returns nil,nil when absent
	SaveDEKFile func([]byte) error
}

// Sealer seals/unseals the CA key with a DEK established per Options.
type Sealer struct {
	mode string
	dek  []byte // nil in ModeOff
}

// NewSealer establishes the DEK fail-closed. It NEVER silently downgrades: an
// unavailable keystore with no passphrase fallback is an error, not plaintext.
func NewSealer(opts Options) (*Sealer, error) {
	switch opts.Mode {
	case ModeOff:
		return &Sealer{mode: ModeOff}, nil
	case ModeKeystore:
		return newKeystoreSealer(opts)
	case ModePassphraseEnv, ModePassphraseFile:
		return newPassphraseSealer(opts)
	default:
		return nil, fmt.Errorf("crypto: unknown key-encryption mode %q", opts.Mode)
	}
}

func newKeystoreSealer(opts Options) (*Sealer, error) {
	if opts.KeyStore == nil || !opts.KeyStore.Available() {
		return nil, fmt.Errorf("crypto: keystore mode requested but no OS keystore is available on this host — set crypto.key_encryption to passphrase-env or passphrase-file")
	}
	dek, err := opts.KeyStore.Get(keystoreService, keystoreAccount)
	if errors.Is(err, ErrNotFound) {
		if dek, err = NewDEK(); err != nil {
			return nil, err
		}
		if err := opts.KeyStore.Set(keystoreService, keystoreAccount, dek); err != nil {
			return nil, fmt.Errorf("crypto: persist DEK to keystore: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("crypto: read DEK from keystore: %w", err)
	}
	if len(dek) != DEKSize {
		return nil, fmt.Errorf("crypto: keystore DEK has wrong size %d (corruption?)", len(dek))
	}
	return &Sealer{mode: opts.Mode, dek: dek}, nil
}

func newPassphraseSealer(opts Options) (*Sealer, error) {
	if len(opts.Passphrase) == 0 {
		return nil, fmt.Errorf("crypto: %s mode requires a non-empty passphrase", opts.Mode)
	}
	if opts.LoadDEKFile == nil || opts.SaveDEKFile == nil {
		return nil, fmt.Errorf("crypto: passphrase mode requires DEK-file load/save hooks")
	}
	wrapped, err := opts.LoadDEKFile()
	if err != nil {
		return nil, fmt.Errorf("crypto: load wrapped DEK: %w", err)
	}
	var dek []byte
	if len(wrapped) == 0 {
		if dek, err = NewDEK(); err != nil {
			return nil, err
		}
		w, err := WrapDEK(opts.Passphrase, dek)
		if err != nil {
			return nil, err
		}
		if err := opts.SaveDEKFile(w); err != nil {
			return nil, fmt.Errorf("crypto: save wrapped DEK: %w", err)
		}
	} else {
		if dek, err = UnwrapDEK(opts.Passphrase, wrapped); err != nil {
			return nil, err
		}
	}
	return &Sealer{mode: opts.Mode, dek: dek}, nil
}

// Seal encrypts plaintext, or returns it unchanged in ModeOff.
func (s *Sealer) Seal(plaintext []byte) ([]byte, error) {
	if s.mode == ModeOff {
		return plaintext, nil
	}
	return Encrypt(s.dek, plaintext)
}

// Unseal decrypts an envelope, or returns it unchanged in ModeOff.
func (s *Sealer) Unseal(ciphertext []byte) ([]byte, error) {
	if s.mode == ModeOff {
		return ciphertext, nil
	}
	return Decrypt(s.dek, ciphertext)
}

// Mode returns the configured mode (for doctor/logging).
func (s *Sealer) Mode() string { return s.mode }

// NewOSKeyStore returns the platform OS keystore backend.
func NewOSKeyStore() KeyStore { return newOSKeyStore() }
```

- [ ] Run `go test ./internal/security/crypto/`. Expect PASS.
- [ ] Cross-compile check: `$env:GOOS='linux'; go vet ./internal/security/crypto/; $env:GOOS='darwin'; go vet ./internal/security/crypto/; $env:GOOS=''`.
- [ ] Add the real-keystore smoke test `internal/security/crypto/keystore_real_test.go`:

```go
//go:build keystore_smoke

package crypto

import (
	"bytes"
	"testing"
)

// TestRealKeyStorePersists exercises the actual OS keystore. It is build-tagged
// (keystore_smoke) and never runs in CI, which has no session keyring.
func TestRealKeyStorePersists(t *testing.T) {
	ks := NewOSKeyStore()
	if !ks.Available() {
		t.Skip("no OS keystore available on this host")
	}
	const acct = "smoke-test"
	want := []byte("0123456789abcdef0123456789abcdef")
	if err := ks.Set(keystoreService, acct, want); err != nil {
		t.Fatalf("Set: %v", err)
	}
	t.Cleanup(func() { _ = ks.Delete(keystoreService, acct) })
	got, err := ks.Get(keystoreService, acct)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("keystore round-trip mismatch")
	}
}
```

- [ ] Commit:
  - `git add internal/security/crypto/keystore_windows.go internal/security/crypto/keystore_darwin.go internal/security/crypto/keystore_linux.go internal/security/crypto/keystore_other.go internal/security/crypto/keystore.go internal/security/crypto/manager.go internal/security/crypto/manager_test.go internal/security/crypto/keystore_real_test.go go.mod go.sum`
  - `git commit -m "feat(crypto): platform KeyStore backends and fail-closed Sealer"`

---

## Task 4 — Route `internal/ca` through the sealer + cert/key match + fail-closed

The `ca` package gains a sealer it uses for the CA key only. The `Sealer` is injected so tests use the fake. `Load`/`Init` default to a passthrough sealer when none is set (preserves existing tests until serve wires the real one).

### 4a. Sealed key read/write + cert/key match (failing test first)

- [ ] Write `internal/ca/sealedkey_test.go`:

```go
package ca

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/sentinel/internal/security/crypto"
)

func TestLoadWithSealerRoundTrip(t *testing.T) {
	dir := t.TempDir()
	sealer, _ := crypto.NewSealer(crypto.Options{Mode: crypto.ModeKeystore, KeyStore: crypto.NewFakeKeyStore()})

	c, err := InitWithSealer(dir, sealer)
	if err != nil {
		t.Fatalf("InitWithSealer: %v", err)
	}
	_ = c

	// The on-disk key must be an encrypted envelope, not plaintext PEM.
	raw, err := os.ReadFile(filepath.Join(dir, caKeyFile))
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if !crypto.IsEnvelope(raw) {
		t.Fatal("ca.key is not encrypted on disk")
	}

	// Reload with the same sealer must succeed.
	if _, err := LoadWithSealer(dir, sealer); err != nil {
		t.Fatalf("LoadWithSealer: %v", err)
	}
}

func TestLoadRejectsSwappedCert(t *testing.T) {
	dir := t.TempDir()
	sealer, _ := crypto.NewSealer(crypto.Options{Mode: crypto.ModeKeystore, KeyStore: crypto.NewFakeKeyStore()})
	if _, err := InitWithSealer(dir, sealer); err != nil {
		t.Fatalf("InitWithSealer: %v", err)
	}

	// Overwrite ca.crt with an unrelated CA's cert (different public key).
	other := t.TempDir()
	otherSealer, _ := crypto.NewSealer(crypto.Options{Mode: crypto.ModeKeystore, KeyStore: crypto.NewFakeKeyStore()})
	oc, _ := InitWithSealer(other, otherSealer)
	if err := os.WriteFile(filepath.Join(dir, caCertFile), oc.RootCertPEM(), 0o644); err != nil {
		t.Fatalf("swap cert: %v", err)
	}

	if _, err := LoadWithSealer(dir, sealer); err == nil {
		t.Fatal("expected cert/key public-key mismatch to fail load")
	}
}

func TestLoadFailsClosedOnWrongSealer(t *testing.T) {
	dir := t.TempDir()
	good, _ := crypto.NewSealer(crypto.Options{Mode: crypto.ModeKeystore, KeyStore: crypto.NewFakeKeyStore()})
	if _, err := InitWithSealer(dir, good); err != nil {
		t.Fatalf("InitWithSealer: %v", err)
	}
	// A different keystore → different DEK → cannot unseal.
	wrong, _ := crypto.NewSealer(crypto.Options{Mode: crypto.ModeKeystore, KeyStore: crypto.NewFakeKeyStore()})
	if _, err := LoadWithSealer(dir, wrong); err == nil {
		t.Fatal("expected unseal failure with wrong sealer")
	}
	// The plaintext key must NOT have been regenerated.
	if _, err := os.Stat(filepath.Join(dir, caKeyFile+".plaintext.bak")); err == nil {
		t.Fatal("load must not create a plaintext backup")
	}
}
```

- [ ] Run `go test ./internal/ca/ -run TestLoadWith -run TestLoadRejects -run TestLoadFailsClosed`. Expect FAIL: `undefined: InitWithSealer` / `LoadWithSealer`.
- [ ] Write `internal/ca/sealedkey.go`:

```go
package ca

import (
	"crypto/ecdsa"
	"fmt"
	"os"

	"github.com/inovacc/sentinel/internal/security/crypto"
)

// passthroughSealer is the default when no sealer is injected: it preserves the
// historical plaintext-on-disk behavior for callers (and tests) that have not
// yet been wired to the real sealer.
func passthroughSealer() *crypto.Sealer {
	s, _ := crypto.NewSealer(crypto.Options{Mode: crypto.ModeOff})
	return s
}

// writeKeyPEMSealed encodes key to PEM, seals it, and writes 0600.
func writeKeyPEMSealed(path string, key *ecdsa.PrivateKey, sealer *crypto.Sealer) error {
	pemBytes, err := encodeKeyPEM(key)
	if err != nil {
		return err
	}
	sealed, err := sealer.Seal(pemBytes)
	if err != nil {
		return fmt.Errorf("ca: seal key: %w", err)
	}
	return os.WriteFile(path, sealed, 0o600)
}

// loadKeyPEMSealed reads, unseals (if encrypted), and decodes the CA key.
func loadKeyPEMSealed(path string, sealer *crypto.Sealer) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ca: read key: %w", err)
	}
	pemBytes := raw
	if crypto.IsEnvelope(raw) {
		if pemBytes, err = sealer.Unseal(raw); err != nil {
			return nil, fmt.Errorf("ca: unseal key (fail-closed — NOT regenerating): %w", err)
		}
	}
	return decodeKeyPEM(pemBytes)
}

// certKeyMatch verifies the cert's public key matches the private key (T8.2:
// catches a swapped cert, which is stored world-readable).
func certKeyMatch(c *CA) error {
	priv, ok := c.rootKey.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("ca: root key is not ECDSA")
	}
	pub, ok := c.rootCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("ca: cert public key is not ECDSA")
	}
	if !priv.PublicKey.Equal(pub) {
		return fmt.Errorf("ca: cert/key mismatch — ca.crt does not match ca.key (swapped cert?)")
	}
	return nil
}
```

### 4b. Wire `Init`/`Load`/`LoadOrInit` to accept a sealer

- [ ] In `internal/ca/ca.go`, add the sealer-aware variants and route the existing ones through them. Add a `sealer` field to `CA` and keep the old signatures as thin wrappers for backward compatibility:

  Add to the `CA` struct:
  ```go
  	sealer *crypto.Sealer // seals/unseals rootKey on disk; passthrough by default
  ```

  Add `import "github.com/inovacc/sentinel/internal/security/crypto"`.

  Replace the `writeKeyPEM(keyPath, key)` call in `Init` with a `InitWithSealer` body. Concretely add:
  ```go
  // Init generates a new root CA with plaintext key-at-rest (backward compatible).
  func Init(dir string) (*CA, error) { return InitWithSealer(dir, passthroughSealer()) }

  // InitWithSealer generates a new root CA and seals its key with sealer.
  func InitWithSealer(dir string, sealer *crypto.Sealer) (*CA, error) {
  	// ... identical body to today's Init up to writeCertPEM ...
  	// then:
  	if err := writeKeyPEMSealed(keyPath, key, sealer); err != nil {
  		return nil, fmt.Errorf("ca: write key: %w", err)
  	}
  	return &CA{rootCert: cert, rootKey: key, dir: dir, sealer: sealer}, nil
  }
  ```
  (Move the existing `Init` body into `InitWithSealer`; the old `Init` becomes the wrapper above.)

- [ ] Replace `Load`/`LoadOrInit` similarly:
  ```go
  // Load reads an existing CA, plaintext key-at-rest (backward compatible).
  func Load(dir string) (*CA, error) { return LoadWithSealer(dir, passthroughSealer()) }

  // LoadWithSealer reads an existing CA, unsealing the key with sealer and
  // verifying the cert matches the key. It fails closed and never regenerates.
  func LoadWithSealer(dir string, sealer *crypto.Sealer) (*CA, error) {
  	certPath := filepath.Join(dir, caCertFile)
  	keyPath := filepath.Join(dir, caKeyFile)

  	certPEM, err := os.ReadFile(certPath)
  	if err != nil {
  		return nil, fmt.Errorf("ca: read cert: %w", err)
  	}
  	cert, err := decodeCertPEM(certPEM)
  	if err != nil {
  		return nil, fmt.Errorf("ca: decode cert: %w", err)
  	}
  	key, err := loadKeyPEMSealed(keyPath, sealer)
  	if err != nil {
  		return nil, err
  	}
  	c := &CA{rootCert: cert, rootKey: key, dir: dir, sealer: sealer}
  	if err := certKeyMatch(c); err != nil {
  		return nil, err
  	}
  	return c, nil
  }

  // LoadOrInitWithSealer loads if exists, else initializes, both sealed.
  func LoadOrInitWithSealer(dir string, sealer *crypto.Sealer) (*CA, error) {
  	if _, err := os.Stat(filepath.Join(dir, caCertFile)); err == nil {
  		return LoadWithSealer(dir, sealer)
  	}
  	return InitWithSealer(dir, sealer)
  }
  ```
  Keep the existing `LoadOrInit(dir)` as `return LoadOrInitWithSealer(dir, passthroughSealer())`.

- [ ] Run `go test ./internal/ca/`. Expect PASS (existing tests still use plaintext passthrough; new tests use the fake-keystore sealer).
- [ ] Commit:
  - `git add internal/ca/ca.go internal/ca/sealedkey.go internal/ca/sealedkey_test.go`
  - `git commit -m "feat(ca): route CA key through the sealer, verify cert/key match, fail closed"`

---

## Task 5 — Plaintext → encrypted migration (`.plaintext.bak`, idempotent, abort-safe)

- [ ] Add to `internal/ca/sealedkey_test.go`:

```go
func TestMigrateEncryptsPlaintextKey(t *testing.T) {
	dir := t.TempDir()
	// Create a plaintext CA (passthrough sealer writes PEM).
	if _, err := Init(dir); err != nil {
		t.Fatalf("Init plaintext: %v", err)
	}
	keyPath := filepath.Join(dir, caKeyFile)
	raw, _ := os.ReadFile(keyPath)
	if crypto.IsEnvelope(raw) {
		t.Fatal("precondition: key should be plaintext")
	}

	sealer, _ := crypto.NewSealer(crypto.Options{Mode: crypto.ModeKeystore, KeyStore: crypto.NewFakeKeyStore()})
	migrated, err := MigrateKeyAtRest(dir, sealer)
	if err != nil {
		t.Fatalf("MigrateKeyAtRest: %v", err)
	}
	if !migrated {
		t.Fatal("expected migration to occur")
	}
	enc, _ := os.ReadFile(keyPath)
	if !crypto.IsEnvelope(enc) {
		t.Fatal("key not encrypted after migration")
	}
	bak, err := os.ReadFile(keyPath + ".plaintext.bak")
	if err != nil {
		t.Fatalf("backup missing: %v", err)
	}
	if !cryptoEqual(bak, raw) {
		t.Fatal("backup does not match original plaintext")
	}
	// Backup is 0600.
	fi, _ := os.Stat(keyPath + ".plaintext.bak")
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode = %v, want 0600", fi.Mode().Perm())
	}

	// Idempotent: a second migration is a no-op.
	again, err := MigrateKeyAtRest(dir, sealer)
	if err != nil {
		t.Fatalf("second MigrateKeyAtRest: %v", err)
	}
	if again {
		t.Fatal("second migration must be a no-op")
	}
}

func TestMigrateAbortLeavesPlaintextIntact(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(dir); err != nil {
		t.Fatalf("Init: %v", err)
	}
	keyPath := filepath.Join(dir, caKeyFile)
	before, _ := os.ReadFile(keyPath)

	// A sealer whose keystore is unavailable cannot be constructed; simulate a
	// DEK-establishment failure by passing a nil sealer → MigrateKeyAtRest errors.
	if _, err := MigrateKeyAtRest(dir, nil); err == nil {
		t.Fatal("expected error with nil sealer")
	}
	after, _ := os.ReadFile(keyPath)
	if !cryptoEqual(before, after) {
		t.Fatal("plaintext key must be untouched on abort")
	}
}

func cryptoEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
```

- [ ] Run `go test ./internal/ca/ -run TestMigrate`. Expect FAIL: `undefined: MigrateKeyAtRest`.
- [ ] Add to `internal/ca/sealedkey.go`:

```go
// MigrateKeyAtRest encrypts a plaintext ca.key in place when a sealer is
// available. It is idempotent (already-encrypted → no-op) and abort-safe: the
// encrypted file is written to a temp path and atomically renamed only after the
// original plaintext is preserved as ca.key.plaintext.bak (0600). Returns true
// when a migration was performed.
func MigrateKeyAtRest(dir string, sealer *crypto.Sealer) (bool, error) {
	if sealer == nil {
		return false, fmt.Errorf("ca: migrate requires a sealer")
	}
	keyPath := filepath.Join(dir, caKeyFile)
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return false, fmt.Errorf("ca: read key for migration: %w", err)
	}
	if crypto.IsEnvelope(raw) {
		return false, nil // already encrypted — idempotent no-op
	}
	if sealer.Mode() == crypto.ModeOff {
		return false, nil // off mode keeps plaintext intentionally
	}

	// Validate the plaintext decodes before touching anything (fail-closed).
	key, err := decodeKeyPEM(raw)
	if err != nil {
		return false, fmt.Errorf("ca: plaintext key is invalid, refusing migration: %w", err)
	}

	sealed, err := sealer.Seal(raw)
	if err != nil {
		return false, fmt.Errorf("ca: seal during migration: %w", err)
	}
	_ = key // decoded purely to validate

	// 1. Preserve the original plaintext as a 0600 backup.
	bakPath := keyPath + ".plaintext.bak"
	if err := os.WriteFile(bakPath, raw, 0o600); err != nil {
		return false, fmt.Errorf("ca: write plaintext backup: %w", err)
	}
	// 2. Write the encrypted key to a temp file then atomic-rename over ca.key.
	tmp := keyPath + ".tmp"
	if err := os.WriteFile(tmp, sealed, 0o600); err != nil {
		return false, fmt.Errorf("ca: write encrypted key: %w", err)
	}
	if err := os.Rename(tmp, keyPath); err != nil {
		_ = os.Remove(tmp)
		return false, fmt.Errorf("ca: replace key with encrypted: %w", err)
	}
	return true, nil
}
```

- [ ] Run `go test ./internal/ca/`. Expect PASS.
- [ ] Commit:
  - `git add internal/ca/sealedkey.go internal/ca/sealedkey_test.go`
  - `git commit -m "feat(ca): plaintext->encrypted CA key migration with .plaintext.bak"`

---

## Task 6 — `CryptoConfig` settings block + v4→v5 migration

- [ ] Write `internal/settings/settings_crypto_test.go`:

```go
package settings

import (
	"testing"
	"time"
)

func TestDefaultCryptoConfig(t *testing.T) {
	c := DefaultConfig()
	if c.Crypto.KeyEncryption != "keystore" {
		t.Fatalf("default KeyEncryption = %q, want keystore", c.Crypto.KeyEncryption)
	}
	if c.Crypto.CertValidity != 720*time.Hour {
		t.Fatalf("default CertValidity = %v, want 720h", c.Crypto.CertValidity)
	}
	if c.Crypto.RenewThreshold != 240*time.Hour {
		t.Fatalf("default RenewThreshold = %v, want 240h", c.Crypto.RenewThreshold)
	}
	if c.Crypto.PassphraseEnv != "SENTINEL_CA_PASSPHRASE" {
		t.Fatalf("default PassphraseEnv = %q", c.Crypto.PassphraseEnv)
	}
}

func TestValidateCryptoRejectsBadMode(t *testing.T) {
	c := DefaultConfig()
	c.Crypto.KeyEncryption = "bogus"
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for invalid key_encryption mode")
	}
}

func TestValidateCryptoRequiresPassphraseFile(t *testing.T) {
	c := DefaultConfig()
	c.Crypto.KeyEncryption = "passphrase-file"
	c.Crypto.PassphraseFile = ""
	if err := c.Validate(); err == nil {
		t.Fatal("expected error: passphrase-file mode needs a path")
	}
}

func TestValidateCryptoDurations(t *testing.T) {
	c := DefaultConfig()
	c.Crypto.RenewThreshold = c.Crypto.CertValidity // must be strictly less
	if err := c.Validate(); err == nil {
		t.Fatal("expected error: renew_threshold must be < cert_validity")
	}
	c = DefaultConfig()
	c.Crypto.CertValidity = 0
	if err := c.Validate(); err == nil {
		t.Fatal("expected error: cert_validity must be > 0")
	}
	c = DefaultConfig()
	c.Crypto.CertValidity = 365 * 24 * time.Hour // > 90d hard max
	if err := c.Validate(); err == nil {
		t.Fatal("expected error: cert_validity above max")
	}
}

func TestMigrateV4ToV5AddsCrypto(t *testing.T) {
	c := DefaultConfig()
	c.Version = 4
	c.Crypto = CryptoConfig{} // simulate a v4 file with no crypto block
	changed := c.Migrate(4)
	if !changed {
		t.Fatal("expected migration to change the config")
	}
	if c.Version != CurrentConfigVersion {
		t.Fatalf("version not bumped: %d", c.Version)
	}
	if c.Crypto.KeyEncryption != "keystore" {
		t.Fatal("v4->v5 migration must back-fill crypto defaults")
	}
}
```

- [ ] Run `go test ./internal/settings/ -run TestCrypto -run TestMigrateV4 -run TestValidateCrypto -run TestDefaultCrypto`. Expect FAIL: `c.Crypto undefined` / `CurrentConfigVersion` still 4.
- [ ] In `internal/settings/settings.go`, bump the version and add the block. Edit the const:
  ```go
  const CurrentConfigVersion = 5
  ```
- [ ] Add `Crypto CryptoConfig \`yaml:"crypto"\`` to the `Config` struct (after `Limits`).
- [ ] Add the type + defaults (mirror `defaultLimitsConfig`/`defaultAuditConfig`):
  ```go
  // CryptoConfig controls CA-key-at-rest protection and cert lifetime (Phase 3.4).
  type CryptoConfig struct {
  	// KeyEncryption is one of: keystore | passphrase-env | passphrase-file | off.
  	KeyEncryption  string        `yaml:"key_encryption"`
  	PassphraseEnv  string        `yaml:"passphrase_env"`  // env var name (passphrase-env)
  	PassphraseFile string        `yaml:"passphrase_file"` // path (passphrase-file)
  	CertValidity   time.Duration `yaml:"cert_validity"`   // new device certs (default 720h)
  	RenewThreshold time.Duration `yaml:"renew_threshold"` // auto-renew own cert under this (240h)
  }

  // maxCertValidity caps cert_validity to keep certs short-lived (T2.3).
  const maxCertValidity = 90 * 24 * time.Hour

  // defaultCryptoConfig is the single source of truth shared by DefaultConfig and
  // Migrate so the two cannot drift.
  func defaultCryptoConfig() CryptoConfig {
  	return CryptoConfig{
  		KeyEncryption:  "keystore",
  		PassphraseEnv:  "SENTINEL_CA_PASSPHRASE",
  		PassphraseFile: "",
  		CertValidity:   720 * time.Hour,
  		RenewThreshold: 240 * time.Hour,
  	}
  }
  ```
- [ ] Add `Crypto: defaultCryptoConfig(),` to the `DefaultConfig()` return literal (after `Limits:`).
- [ ] Add validation to `Validate()` (before `return nil`):
  ```go
  	// Check crypto block (Phase 3.4).
  	switch c.Crypto.KeyEncryption {
  	case "keystore", "passphrase-env", "passphrase-file", "off":
  	default:
  		return fmt.Errorf("invalid crypto.key_encryption %q (want keystore|passphrase-env|passphrase-file|off)", c.Crypto.KeyEncryption)
  	}
  	if c.Crypto.KeyEncryption == "passphrase-env" && c.Crypto.PassphraseEnv == "" {
  		return fmt.Errorf("crypto.passphrase_env is required for passphrase-env mode")
  	}
  	if c.Crypto.KeyEncryption == "passphrase-file" && c.Crypto.PassphraseFile == "" {
  		return fmt.Errorf("crypto.passphrase_file is required for passphrase-file mode")
  	}
  	if c.Crypto.CertValidity <= 0 {
  		return fmt.Errorf("crypto.cert_validity must be > 0, got %v", c.Crypto.CertValidity)
  	}
  	if c.Crypto.CertValidity > maxCertValidity {
  		return fmt.Errorf("crypto.cert_validity must be <= %v, got %v", maxCertValidity, c.Crypto.CertValidity)
  	}
  	if c.Crypto.RenewThreshold <= 0 || c.Crypto.RenewThreshold >= c.Crypto.CertValidity {
  		return fmt.Errorf("crypto.renew_threshold must satisfy 0 < threshold < cert_validity, got %v", c.Crypto.RenewThreshold)
  	}
  ```
- [ ] Add the migration to `Migrate()` (before the `c.Version < CurrentConfigVersion` block):
  ```go
  	// v4 → v5 introduced the crypto: block. A file written at v4 that omits it
  	// already carries defaults via Load's overlay, but an explicit zero block
  	// (or an unmigrated file) must be back-filled to the safe defaults.
  	if fromVersion < 5 && c.Crypto == (CryptoConfig{}) {
  		c.Crypto = defaultCryptoConfig()
  		changed = true
  	}
  ```
- [ ] Run `go test ./internal/settings/`. Expect PASS.
- [ ] Commit:
  - `git add internal/settings/settings.go internal/settings/settings_crypto_test.go`
  - `git commit -m "feat(settings): add CryptoConfig block, v4->v5 migration"`

---

## Task 7 — Fleet registry revocation columns + `Revoke`/`Unrevoke` + audit

### 7a. Audit events first (the registry emits them)

- [ ] In `internal/audit/catalog.go`, add constants in the `const (...)` block:
  ```go
  	EventDeviceRevoked    = "device.revoked"
  	EventDeviceUnrevoked  = "device.unrevoked"
  	EventCAKeySealed      = "cakey.sealed"
  	EventCAKeyUnsealFail  = "cakey.unseal_failed"
  	EventCertAutorenew    = "cert.autorenew"
  ```
- [ ] Add them to the `catalog` map:
  ```go
  	EventDeviceRevoked:    Critical,
  	EventDeviceUnrevoked:  Critical,
  	EventCAKeySealed:      Critical,
  	EventCAKeyUnsealFail:  Critical,
  	EventCertAutorenew:    Routine,
  ```
- [ ] Run `go test ./internal/audit/`. Expect PASS (the completeness test `TestEveryCatalogEventHasCriticality` passes because each new constant is in both the const block and the map; add the new constants to `catalog_test.go`'s table if it enumerates explicit pairs — append `{EventDeviceRevoked, Critical}`, `{EventDeviceUnrevoked, Critical}`, `{EventCAKeySealed, Critical}`, `{EventCAKeyUnsealFail, Critical}`, `{EventCertAutorenew, Routine}`).
- [ ] Commit:
  - `git add internal/audit/catalog.go internal/audit/catalog_test.go`
  - `git commit -m "feat(audit): add revocation, CA-seal, and autorenew event types"`

### 7b. Registry columns + methods (failing test first)

- [ ] Write `internal/fleet/registry_revoke_test.go`:

```go
package fleet

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func newTestRegistry(t *testing.T) *Registry {
	t.Helper()
	db, err := sql.Open("sqlite", "file:revoke_"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	r, err := NewRegistry(db)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return r
}

func TestRevokeUnrevokeRoundTrip(t *testing.T) {
	r := newTestRegistry(t)
	if err := r.AddPending(&Device{DeviceID: "DEV1", Role: "reader"}); err != nil {
		t.Fatalf("AddPending: %v", err)
	}
	if r.IsRevoked("DEV1") {
		t.Fatal("new device should not be revoked")
	}
	if err := r.Revoke("DEV1", "stolen laptop"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if !r.IsRevoked("DEV1") {
		t.Fatal("device should be revoked")
	}
	d, err := r.Get("DEV1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !d.Revoked || d.RevokedReason != "stolen laptop" || d.RevokedAt.IsZero() {
		t.Fatalf("revocation fields not persisted: %+v", d)
	}
	if err := r.Unrevoke("DEV1"); err != nil {
		t.Fatalf("Unrevoke: %v", err)
	}
	if r.IsRevoked("DEV1") {
		t.Fatal("device should be un-revoked")
	}
}

func TestRevokeUnknownDeviceFails(t *testing.T) {
	r := newTestRegistry(t)
	if err := r.Revoke("NOPE", ""); err == nil {
		t.Fatal("expected error revoking unknown device")
	}
}

func TestMigrationAddsRevokedColumnsToExistingDB(t *testing.T) {
	db, err := sql.Open("sqlite", "file:legacy?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	// Create a pre-revocation table (no revoked columns), then construct the
	// registry which must add them via the additive migration.
	_, err = db.Exec(`CREATE TABLE fleet_devices (
		device_id TEXT PRIMARY KEY, hostname TEXT, os TEXT, arch TEXT, role TEXT,
		status TEXT, address TEXT, cert_pem BLOB, last_seen_at INTEGER,
		created_at INTEGER, metadata TEXT, ca_fingerprint TEXT, ca_cert_pem BLOB)`)
	if err != nil {
		t.Fatalf("legacy schema: %v", err)
	}
	r, err := NewRegistry(db)
	if err != nil {
		t.Fatalf("NewRegistry on legacy db: %v", err)
	}
	if err := r.AddPending(&Device{DeviceID: "X", Role: "reader"}); err != nil {
		t.Fatalf("AddPending after migration: %v", err)
	}
	if r.IsRevoked("X") {
		t.Fatal("migrated row should default to not-revoked")
	}
}
```

- [ ] Run `go test ./internal/fleet/ -run TestRevoke -run TestMigration`. Expect FAIL: `d.Revoked undefined` / `r.Revoke undefined`.
- [ ] In `internal/fleet/registry.go`, extend the `Device` struct (after `CACertPEM`):
  ```go
  	// Revoked marks a device whose certificate is no longer accepted at the mTLS
  	// handshake (T8.4 local revocation). RevokedAt/RevokedReason are set by Revoke.
  	Revoked       bool      `json:"revoked"`
  	RevokedAt     time.Time `json:"revoked_at,omitempty"`
  	RevokedReason string    `json:"revoked_reason,omitempty"`
  ```
- [ ] Extend the additive migration slice in `migrate()`:
  ```go
  		{"revoked", "ALTER TABLE fleet_devices ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0"},
  		{"revoked_at", "ALTER TABLE fleet_devices ADD COLUMN revoked_at TEXT"},
  		{"reason", "ALTER TABLE fleet_devices ADD COLUMN reason TEXT"},
  ```
  Also add `revoked INTEGER NOT NULL DEFAULT 0`, `revoked_at TEXT`, `reason TEXT` to the `CREATE TABLE IF NOT EXISTS` body so fresh DBs have them.
- [ ] Update both SELECT column lists (in `Get` and `List`) to append `, revoked, revoked_at, reason` and the `AddPending` INSERT to set defaults (`revoked` defaults via the column, so leave INSERT as-is — it omits the new columns and they take their DEFAULT/NULL).
- [ ] Update `scanDevice` and `scanDeviceRow` to scan the three new columns:
  ```go
  	var revoked int
  	var revokedAt, reason sql.NullString
  	err := row.Scan(&d.DeviceID, &d.Hostname, &d.OS, &d.Arch, &d.Role, &d.Status,
  		&d.Address, &d.CertPEM, &lastSeen, &created, &meta,
  		&d.CAFingerprint, &d.CACertPEM, &revoked, &revokedAt, &reason)
  	// ... existing error/timestamp handling ...
  	d.Revoked = revoked != 0
  	if revokedAt.Valid && revokedAt.String != "" {
  		if ts, perr := time.Parse(time.RFC3339, revokedAt.String); perr == nil {
  			d.RevokedAt = ts
  		}
  	}
  	d.RevokedReason = reason.String
  ```
  (Apply the same scan changes to `scanDeviceRow` with `rows.Scan`.)
- [ ] Add the methods at the end of the file:
  ```go
  // Revoke marks a device revoked and records the reason + timestamp. It emits the
  // critical device.revoked audit event and fails closed: on audit-write failure
  // the device is NOT revoked (so the action is never applied unrecorded).
  func (r *Registry) Revoke(deviceID, reason string) error {
  	if _, err := r.Get(deviceID); err != nil {
  		return fmt.Errorf("fleet: revoke: %w", err)
  	}
  	if aerr := r.auditLog.Record(context.Background(), audit.Event{
  		Type:    audit.EventDeviceRevoked,
  		Outcome: audit.OutcomeAllow,
  		Target:  deviceID,
  		Detail:  map[string]any{"device_id": deviceID, "reason": reason},
  	}); aerr != nil {
  		return fmt.Errorf("fleet: refusing to revoke device unaudited: %w", aerr)
  	}
  	now := time.Now().UTC().Format(time.RFC3339)
  	res, err := r.db.Exec(
  		`UPDATE fleet_devices SET revoked = 1, revoked_at = ?, reason = ? WHERE device_id = ?`,
  		now, reason, deviceID,
  	)
  	if err != nil {
  		return fmt.Errorf("fleet: revoke device: %w", err)
  	}
  	if n, _ := res.RowsAffected(); n == 0 {
  		return fmt.Errorf("fleet: device %s not found", deviceID)
  	}
  	return nil
  }

  // Unrevoke clears a device's revoked state. It emits the critical
  // device.unrevoked event and fails closed.
  func (r *Registry) Unrevoke(deviceID string) error {
  	if _, err := r.Get(deviceID); err != nil {
  		return fmt.Errorf("fleet: unrevoke: %w", err)
  	}
  	if aerr := r.auditLog.Record(context.Background(), audit.Event{
  		Type:    audit.EventDeviceUnrevoked,
  		Outcome: audit.OutcomeAllow,
  		Target:  deviceID,
  		Detail:  map[string]any{"device_id": deviceID},
  	}); aerr != nil {
  		return fmt.Errorf("fleet: refusing to unrevoke device unaudited: %w", aerr)
  	}
  	res, err := r.db.Exec(
  		`UPDATE fleet_devices SET revoked = 0, revoked_at = NULL, reason = NULL WHERE device_id = ?`,
  		deviceID,
  	)
  	if err != nil {
  		return fmt.Errorf("fleet: unrevoke device: %w", err)
  	}
  	if n, _ := res.RowsAffected(); n == 0 {
  		return fmt.Errorf("fleet: device %s not found", deviceID)
  	}
  	return nil
  }

  // IsRevoked reports whether the device is currently revoked. An unknown device
  // is reported not-revoked (the handshake's CA/pin checks reject unknowns).
  func (r *Registry) IsRevoked(deviceID string) bool {
  	var revoked int
  	if err := r.db.QueryRow(
  		`SELECT revoked FROM fleet_devices WHERE device_id = ?`, deviceID,
  	).Scan(&revoked); err != nil {
  		return false
  	}
  	return revoked != 0
  }
  ```
- [ ] Run `go test ./internal/fleet/`. Expect PASS.
- [ ] Commit:
  - `git add internal/fleet/registry.go internal/fleet/registry_revoke_test.go`
  - `git commit -m "feat(fleet): revoked columns and Revoke/Unrevoke with audit"`

---

## Task 8 — mTLS rejects revoked peers + live-connection sweep

### 8a. `VerifyPeer` hook on the server config (failing test first)

- [ ] Write `pkg/transport/mtls_revoke_test.go`:

```go
package transport

import (
	"crypto/x509"
	"errors"
	"testing"
)

func TestServerConfigRejectsRevokedPeer(t *testing.T) {
	revoked := errors.New("revoked")
	cfg := MTLSConfig{
		CertPEM:   testCertPEM(t),
		KeyPEM:    testKeyPEM(t),
		CACertPEM: testCAPEM(t),
		VerifyPeer: func(_ *x509.Certificate) error { return revoked },
	}
	tlsCfg, err := NewMTLSServerConfig(cfg)
	if err != nil {
		t.Fatalf("NewMTLSServerConfig: %v", err)
	}
	if tlsCfg.VerifyPeerCertificate == nil {
		t.Fatal("expected VerifyPeerCertificate to be wired when VerifyPeer is set")
	}
	// Feed the hook a valid leaf; it must surface the VerifyPeer error.
	leaf := testLeafDER(t)
	err = tlsCfg.VerifyPeerCertificate([][]byte{leaf}, nil)
	if !errors.Is(err, revoked) {
		t.Fatalf("expected revoked error, got %v", err)
	}
}

func TestServerConfigNilVerifyPeerAllows(t *testing.T) {
	cfg := MTLSConfig{CertPEM: testCertPEM(t), KeyPEM: testKeyPEM(t), CACertPEM: testCAPEM(t)}
	tlsCfg, err := NewMTLSServerConfig(cfg)
	if err != nil {
		t.Fatalf("NewMTLSServerConfig: %v", err)
	}
	if tlsCfg.VerifyPeerCertificate != nil {
		t.Fatal("no VerifyPeer set → no custom verification hook")
	}
}
```

> Helpers `testCertPEM`/`testKeyPEM`/`testCAPEM`/`testLeafDER` generate a throwaway CA + device cert with `internal/ca` into `t.TempDir()`. Reuse any existing transport test helper if one exists; otherwise add them in this test file using `ca.InitWithSealer(t.TempDir(), passthrough)` + `SignDevice`.

- [ ] Run `go test ./pkg/transport/ -run TestServerConfig`. Expect FAIL: `unknown field VerifyPeer`.
- [ ] In `pkg/transport/mtls.go`, add the field to `MTLSConfig`:
  ```go
  	// VerifyPeer, when non-nil, is called during the mTLS handshake with the
  	// peer's verified leaf certificate. Returning an error rejects the handshake
  	// (used for local revocation, T8.4). It runs AFTER chain verification.
  	VerifyPeer func(leaf *x509.Certificate) error
  ```
- [ ] In `NewMTLSServerConfig`, after building `caPool` and before the return, wire the hook:
  ```go
  	tlsCfg := &tls.Config{
  		Certificates: []tls.Certificate{cert},
  		ClientAuth:   tls.RequireAndVerifyClientCert,
  		ClientCAs:    caPool,
  		MinVersion:   tls.VersionTLS13,
  	}
  	if cfg.VerifyPeer != nil {
  		verify := cfg.VerifyPeer
  		tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
  			if len(rawCerts) == 0 {
  				return fmt.Errorf("mtls: no peer certificate")
  			}
  			leaf, err := x509.ParseCertificate(rawCerts[0])
  			if err != nil {
  				return fmt.Errorf("mtls: parse peer cert: %w", err)
  			}
  			return verify(leaf)
  		}
  	}
  	return tlsCfg, nil
  ```
  (Replace the existing `return &tls.Config{...}, nil` with the above.)
- [ ] Run `go test ./pkg/transport/`. Expect PASS.
- [ ] Commit:
  - `git add pkg/transport/mtls.go pkg/transport/mtls_revoke_test.go`
  - `git commit -m "feat(transport): VerifyPeer hook on mTLS server config for revocation"`

### 8b. Revocation-check callback (resolves device ID, audits rejection)

- [ ] In `cmd/serve.go`, add a builder that turns the registry into a `VerifyPeer` func. It resolves the Syncthing-style device ID from the leaf and rejects revoked peers, emitting the existing `pairing.reject` event with `Detail{reason:"revoked"}` (per spec — no new rejection event):

```go
// buildRevocationVerifier returns an mTLS VerifyPeer hook that rejects a peer
// whose device ID is revoked in the registry. A rejection emits pairing.reject
// (critical) with reason="revoked"; an audit-write failure still rejects (the
// handshake fails closed regardless).
func buildRevocationVerifier(registry *fleet.Registry, auditLog audit.Logger) func(*x509.Certificate) error {
	return func(leaf *x509.Certificate) error {
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
		deviceID, err := ca.DeviceID(certPEM)
		if err != nil {
			return fmt.Errorf("mtls: derive peer device id: %w", err)
		}
		if registry.IsRevoked(deviceID) {
			_ = auditLog.Record(context.Background(), audit.Event{
				Type:    audit.EventPairingReject,
				Outcome: audit.OutcomeDeny,
				Target:  deviceID,
				Detail:  map[string]any{"device_id": deviceID, "reason": "revoked"},
			})
			return fmt.Errorf("mtls: peer %s is revoked", deviceID)
		}
		return nil
	}
}
```

- [ ] Wire it where the gRPC server's mTLS config is built. The gRPC server is created at `sentinelgrpc.NewServer(certPEM, keyPEM, authority.RootCertPEM(), policy, auditLog, ...)`. Add a `VerifyPeer` option to that server constructor (mirror existing variadic options) and pass `buildRevocationVerifier(registry, auditLog)`. The server's internal `NewMTLSServerConfig` call sets `cfg.VerifyPeer` from it.
  - If `sentinelgrpc.NewServer` does not currently accept transport options, add `WithPeerVerifier(func(*x509.Certificate) error)` to `internal/grpc/server.go` and thread it into the `transport.MTLSConfig` the server builds. (Inspect `internal/grpc/server.go` for the exact option pattern at implementation time; the seam is the `MTLSConfig.VerifyPeer` field added in 8a.)

### 8c. Live-connection sweep on heartbeat (failing test first)

- [ ] Add to `cmd/serve_test.go` (or a new `cmd/serve_revoke_test.go`) a test that a revoked device's active session is torn down on the stale-sweep tick. Since live-connection teardown reuses `session.Manager.CheckStale`, the sweep helper `sweepRevokedSessions(registry, sessionMgr)` must mark a revoked device's sessions for closure. Test it at the helper level:

```go
func TestSweepRevokedSessionsClosesRevoked(t *testing.T) {
	// Build an in-memory registry + session manager, register an active session
	// owned by DEV1, revoke DEV1, run the sweep, and assert the session is gone.
	// (Construct via the same helpers used by other cmd tests.)
}
```

> Implementation note: a session's owning device ID is available where sessions are created (the RBAC actor). If the session manager does not currently track owner device IDs, the minimal v1 closes the gRPC connection at the next heartbeat by having the heartbeat handler call `registry.IsRevoked(actorDeviceID)` and returning a `codes.PermissionDenied` status, which terminates the stream. Prefer this in-band check over a separate sweeper if owner tracking is absent — document the choice in the test.

- [ ] Implement the chosen mechanism (in-band heartbeat revocation check is preferred for v1; it requires only the actor device ID already on the context). Add to the session/heartbeat gRPC handler:
  ```go
  if registry.IsRevoked(actorDeviceID) {
  	return status.Errorf(codes.PermissionDenied, "device revoked")
  }
  ```
- [ ] Run `go test ./cmd/ ./internal/grpc/`. Expect PASS.
- [ ] Commit:
  - `git add cmd/serve.go internal/grpc/ cmd/serve_revoke_test.go`
  - `git commit -m "feat(serve): reject revoked peers at handshake and close live revoked sessions"`

---

## Task 9 — `sentinel revoke` / `unrevoke` CLI + `fleet list` revoked column

- [ ] Write `cmd/revoke_test.go`:

```go
package cmd

import "testing"

func TestRevokeCommandMarksDevice(t *testing.T) {
	// Point datadir at a temp dir, init a registry, add a device, run the revoke
	// command's RunE, then assert the registry reports it revoked. Mirror the
	// setup used by existing cmd/*_test.go (temp HOME / SENTINEL_DATA_DIR).
}
```

- [ ] Run `go test ./cmd/ -run TestRevokeCommand`. Expect FAIL: `undefined: newRevokeCmd`.
- [ ] Write `cmd/revoke.go`:

```go
package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func newRevokeCmd() *cobra.Command {
	var reason string
	cmd := &cobra.Command{
		Use:   "revoke [device-id]",
		Short: "Revoke a device so its certificate is rejected at the mTLS handshake",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			reg, cleanup, err := openRegistryAudited()
			if err != nil {
				return err
			}
			defer cleanup()
			if err := reg.Revoke(args[0], reason); err != nil {
				return fmt.Errorf("revoke device: %w", err)
			}
			return emitJSON(struct {
				Status   string `json:"status"`
				DeviceID string `json:"device_id"`
				Reason   string `json:"reason,omitempty"`
			}{"revoked", args[0], reason})
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "", "reason for revocation (recorded in the audit log)")
	return cmd
}

func newUnrevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unrevoke [device-id]",
		Short: "Restore a previously revoked device",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			reg, cleanup, err := openRegistryAudited()
			if err != nil {
				return err
			}
			defer cleanup()
			if err := reg.Unrevoke(args[0]); err != nil {
				return fmt.Errorf("unrevoke device: %w", err)
			}
			return emitJSON(struct {
				Status   string `json:"status"`
				DeviceID string `json:"device_id"`
			}{"unrevoked", args[0]})
		},
	}
}

// emitJSON writes v as indented JSON to stdout (matches fleet command style).
func emitJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
```

- [ ] Register both commands on the root command. Find where `newFleetCmd()`/`newRenewCmd()` are added (the root command assembly, likely `cmd/root.go`) and add `rootCmd.AddCommand(newRevokeCmd(), newUnrevokeCmd())`.
- [ ] `fleet list` already serializes the full `Device` (now including `revoked`/`revoked_at`/`revoked_reason`), so JSON output carries revocation automatically — no change needed beyond Task 7's struct fields. Confirm by asserting in `cmd/revoke_test.go` that `fleet list` JSON includes `"revoked": true` after a revoke.
- [ ] Run `go test ./cmd/`. Expect PASS.
- [ ] Commit:
  - `git add cmd/revoke.go cmd/revoke_test.go cmd/root.go`
  - `git commit -m "feat(cmd): add sentinel revoke/unrevoke; fleet list shows revoked"`

---

## Task 10 — Short-lived cert issuance + own-cert auto-renewal

### 10a. Configurable cert validity + self re-sign (failing test first)

- [ ] Write `internal/ca/validity_test.go`:

```go
package ca

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestSignDeviceForHonorsValidity(t *testing.T) {
	c, err := Init(t.TempDir())
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	certPEM, _, err := c.SignDeviceFor(RoleReader, 720*time.Hour)
	if err != nil {
		t.Fatalf("SignDeviceFor: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)
	got := cert.NotAfter.Sub(cert.NotBefore)
	// Allow a small slop for the issuance timestamp.
	if got < 719*time.Hour || got > 721*time.Hour {
		t.Fatalf("validity = %v, want ~720h", got)
	}
}

func TestSignDeviceDefaultsToOneYear(t *testing.T) {
	c, _ := Init(t.TempDir())
	certPEM, _, err := c.SignDevice(RoleReader) // unchanged default behavior
	if err != nil {
		t.Fatalf("SignDevice: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)
	got := cert.NotAfter.Sub(cert.NotBefore)
	if got < 364*24*time.Hour {
		t.Fatalf("default validity = %v, want ~1y", got)
	}
}
```

- [ ] Run `go test ./internal/ca/ -run TestSignDeviceFor -run TestSignDeviceDefaults`. Expect FAIL: `undefined: SignDeviceFor`.
- [ ] In `internal/ca/ca.go`, refactor `SignDevice` to delegate to `SignDeviceFor`:
  ```go
  // SignDevice signs a 1-year device cert (backward-compatible default).
  func (c *CA) SignDevice(role string) (certPEM, keyPEM []byte, err error) {
  	return c.SignDeviceFor(role, 365*24*time.Hour)
  }

  // SignDeviceFor signs a device cert valid for the given duration (T2.3). The
  // role is embedded in the custom X.509 extension.
  func (c *CA) SignDeviceFor(role string, validity time.Duration) (certPEM, keyPEM []byte, err error) {
  	if !ValidRole(role) {
  		return nil, nil, fmt.Errorf("ca: invalid role %q", role)
  	}
  	// ... existing body, but: NotAfter: now.Add(validity) ...
  }
  ```
  (Move the existing `SignDevice` body into `SignDeviceFor`, changing only `NotAfter: now.Add(365 * 24 * time.Hour)` → `NotAfter: now.Add(validity)`.)
- [ ] Add a self re-sign for auto-renewal:
  ```go
  // ReSignSelf re-issues a fresh device cert for this node's own key reuse is not
  // possible (a new keypair is generated), valid for validity, using the local CA
  // — no peer interaction. Returns the new cert+key PEM for the caller to persist.
  func (c *CA) ReSignSelf(role string, validity time.Duration) (certPEM, keyPEM []byte, err error) {
  	return c.SignDeviceFor(role, validity)
  }
  ```
- [ ] Run `go test ./internal/ca/`. Expect PASS.
- [ ] Commit:
  - `git add internal/ca/ca.go internal/ca/validity_test.go`
  - `git commit -m "feat(ca): configurable cert validity and own-cert re-sign"`

### 10b. Auto-renew goroutine + extend `warnCertExpiry`

- [ ] Write `cmd/autorenew_test.go`:

```go
package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestNeedsAutoRenew(t *testing.T) {
	cases := []struct {
		name      string
		remaining time.Duration
		threshold time.Duration
		want      bool
	}{
		{"well above threshold", 500 * time.Hour, 240 * time.Hour, false},
		{"below threshold", 100 * time.Hour, 240 * time.Hour, true},
		{"expired", -1 * time.Hour, 240 * time.Hour, true},
		{"exactly at threshold", 240 * time.Hour, 240 * time.Hour, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert := &x509.Certificate{NotAfter: time.Now().Add(tc.remaining)}
			if got := needsAutoRenew(cert, tc.threshold); got != tc.want {
				t.Fatalf("needsAutoRenew(%v, %v) = %v, want %v", tc.remaining, tc.threshold, got, tc.want)
			}
		})
	}
}

func TestRenewSelfIfNeededWritesFreshCert(t *testing.T) {
	// Build a CA + a short-lived device cert (remaining < threshold) in a temp
	// cert dir, call renewSelfIfNeeded, and assert device.crt's NotAfter advanced.
	_ = pem.Decode // keep import; real assertions added at implementation time.
}
```

- [ ] Run `go test ./cmd/ -run TestNeedsAutoRenew`. Expect FAIL: `undefined: needsAutoRenew`.
- [ ] Add to `cmd/serve.go`:
  ```go
  // needsAutoRenew reports whether the cert's remaining life is below threshold.
  func needsAutoRenew(cert *x509.Certificate, threshold time.Duration) bool {
  	return time.Until(cert.NotAfter) < threshold
  }

  // renewSelfIfNeeded re-signs this node's own device cert in place when it is
  // within RenewThreshold of expiry, using the local CA (no peer interaction). It
  // emits cert.autorenew (routine) and returns true when a renewal happened.
  func renewSelfIfNeeded(authority *ca.CA, certDir string, role string, cfg settings.CryptoConfig, auditLog audit.Logger, logger *slog.Logger) (bool, error) {
  	certPath := filepath.Join(certDir, "device.crt")
  	keyPath := filepath.Join(certDir, "device.key")
  	certPEM, err := os.ReadFile(certPath)
  	if err != nil {
  		return false, fmt.Errorf("autorenew: read device cert: %w", err)
  	}
  	block, _ := pem.Decode(certPEM)
  	if block == nil {
  		return false, fmt.Errorf("autorenew: device cert unreadable")
  	}
  	cert, err := x509.ParseCertificate(block.Bytes)
  	if err != nil {
  		return false, fmt.Errorf("autorenew: parse device cert: %w", err)
  	}
  	if !needsAutoRenew(cert, cfg.RenewThreshold) {
  		return false, nil
  	}
  	newCert, newKey, err := authority.ReSignSelf(role, cfg.CertValidity)
  	if err != nil {
  		return false, fmt.Errorf("autorenew: re-sign: %w", err)
  	}
  	if err := os.WriteFile(keyPath, newKey, 0o600); err != nil {
  		return false, fmt.Errorf("autorenew: write key: %w", err)
  	}
  	if err := os.WriteFile(certPath, newCert, 0o644); err != nil {
  		return false, fmt.Errorf("autorenew: write cert: %w", err)
  	}
  	_ = auditLog.Record(context.Background(), audit.Event{
  		Type:    audit.EventCertAutorenew,
  		Outcome: audit.OutcomeAllow,
  		Target:  "self",
  		Detail:  map[string]any{"valid_for_hours": int(cfg.CertValidity.Hours())},
  	})
  	logger.Info("auto-renewed own device certificate", "valid_until", time.Now().Add(cfg.CertValidity).Format("2006-01-02"))
  	return true, nil
  }
  ```
  (`role` is the daemon's own role — admin for the self identity; read it from the existing device cert's role extension via `ca.RoleFromCert` if available, else default `ca.RoleAdmin`.)
- [ ] Start the renewal goroutine in `runDaemonCtx`, alongside the existing background goroutines (search for the `go func()` blocks). It ticks (e.g. every 6h), calls `renewSelfIfNeeded`, and exits on `ctx.Done()`:
  ```go
  go func() {
  	ticker := time.NewTicker(6 * time.Hour)
  	defer ticker.Stop()
  	for {
  		select {
  		case <-ctx.Done():
  			return
  		case <-ticker.C:
  			if _, err := renewSelfIfNeeded(authority, certDir, selfRole, cfg.Crypto, auditLog, logger); err != nil {
  				logger.Warn("own-cert auto-renew failed", "err", err)
  			}
  		}
  	}
  }()
  ```
  Also run `renewSelfIfNeeded` once at startup, right after the existing `warnCertExpiry(logger, certPEM)` call.
- [ ] Run `go test ./cmd/`. Expect PASS.
- [ ] Commit:
  - `git add cmd/serve.go cmd/autorenew_test.go`
  - `git commit -m "feat(serve): own-cert auto-renewal goroutine with cert.autorenew audit"`

---

## Task 11 — `serve.go` sealer wiring + migration on start + emit `cakey.sealed`

- [ ] In `cmd/serve.go`, build the sealer from config and route CA load through it. Add a helper:
  ```go
  // buildSealer constructs the CA-key sealer from config, reading the passphrase
  // from the configured source. It fails closed: an unavailable keystore with no
  // passphrase fallback is a fatal startup error, never a silent plaintext.
  func buildSealer(cfg *settings.Config) (*crypto.Sealer, error) {
  	caDir, err := datadir.CADir()
  	if err != nil {
  		return nil, err
  	}
  	dekPath := filepath.Join(caDir, "ca.key.dek")
  	opts := crypto.Options{
  		Mode:     cfg.Crypto.KeyEncryption,
  		KeyStore: crypto.NewOSKeyStore(),
  		LoadDEKFile: func() ([]byte, error) {
  			b, rerr := os.ReadFile(dekPath)
  			if errors.Is(rerr, os.ErrNotExist) {
  				return nil, nil
  			}
  			return b, rerr
  		},
  		SaveDEKFile: func(b []byte) error { return os.WriteFile(dekPath, b, 0o600) },
  	}
  	switch cfg.Crypto.KeyEncryption {
  	case crypto.ModePassphraseEnv:
  		opts.Passphrase = []byte(os.Getenv(cfg.Crypto.PassphraseEnv))
  	case crypto.ModePassphraseFile:
  		p, rerr := os.ReadFile(cfg.Crypto.PassphraseFile)
  		if rerr != nil {
  			return nil, fmt.Errorf("read passphrase file: %w", rerr)
  		}
  		opts.Passphrase = []byte(strings.TrimSpace(string(p)))
  	}
  	if cfg.Crypto.KeyEncryption == crypto.ModeOff {
  		slog.Default().Warn("crypto.key_encryption=off — CA key stored in PLAINTEXT (dev only)")
  	}
  	return crypto.NewSealer(opts)
  }
  ```
- [ ] In `buildDaemon` (where the CA is loaded — currently `ensureIdentity()` + `loadDeviceIdentity()`), after the sealer is built: migrate the key at rest, emit `cakey.sealed` on first migration, and on an unseal/build failure classify the error via `clierr` and abort:
  ```go
  sealer, err := buildSealer(cfg)
  if err != nil {
  	if d, ok := clierr.ClassifyCAUnseal(err); ok {
  		return d, fmt.Errorf("%s", d.Error())
  	}
  	return d, fmt.Errorf("build CA sealer: %w", err)
  }
  caDir, _ := datadir.CADir()
  if migrated, merr := ca.MigrateKeyAtRest(caDir, sealer); merr != nil {
  	return d, fmt.Errorf("migrate CA key at rest: %w", merr)
  } else if migrated {
  	logger.Warn("CA key encrypted at rest; a plaintext backup remains — securely delete it",
  		"backup", filepath.Join(caDir, "ca.key.plaintext.bak"))
  	if aerr := auditLog.Record(context.Background(), audit.Event{
  		Type:    audit.EventCAKeySealed,
  		Outcome: audit.OutcomeAllow,
  		Target:  "ca.key",
  		Detail:  map[string]any{"mode": cfg.Crypto.KeyEncryption},
  	}); aerr != nil {
  		return d, fmt.Errorf("refusing to seal CA key unaudited: %w", aerr)
  	}
  }
  ```
  Then change the CA load to `ca.LoadWithSealer(caDir, sealer)`. (Adjust `ensureIdentity`/`loadDeviceIdentity` to accept and use the sealer; `ensureIdentity` should call `ca.LoadOrInitWithSealer`.) Emit `cakey.unseal_failed` (critical) on a load failure before returning the classified error.
- [ ] In `internal/clierr/clierr.go`, add the new kind + classifier:
  ```go
  // KindCAUnseal means the CA private key could not be decrypted at rest.
  // (append after KindCertExpired)
  KindCAUnseal
  ```
  ```go
  const caUnsealRemediation = "The CA private key on disk could not be decrypted. This usually means the OS keystore changed (a different user profile, a re-keyed keyring) or the configured passphrase is wrong. Do NOT delete ca.key — the daemon will never regenerate it. Recover by: restoring the keystore/passphrase, or restoring ca.key.plaintext.bak (if migration created one) and re-running, or setting crypto.key_encryption to the mode that matches how the key was sealed."

  // ClassifyCAUnseal recognizes a CA-key unseal failure (errors wrapping the
  // crypto package's "unseal" / "auth failed" messages) and returns actionable
  // guidance. Unlike Classify, it matches on the unseal error text.
  func ClassifyCAUnseal(err error) (*Diagnostic, bool) {
  	if err == nil {
  		return nil, false
  	}
  	msg := strings.ToLower(err.Error())
  	if strings.Contains(msg, "unseal") || strings.Contains(msg, "auth failed") ||
  		strings.Contains(msg, "no os keystore") || strings.Contains(msg, "wrong passphrase") {
  		return &Diagnostic{
  			Kind:        KindCAUnseal,
  			Summary:     "Cannot decrypt the CA private key at rest.",
  			Detail:      err.Error(),
  			Remediation: caUnsealRemediation,
  			Err:         err,
  		}, true
  	}
  	return nil, false
  }
  ```
- [ ] Add the `checkCAKeyAtRest` doctor check in `cmd/doctor.go`:
  ```go
  // checkCAKeyAtRest reports whether the CA key is encrypted, which mode protects
  // it, and whether a plaintext backup lingers.
  func checkCAKeyAtRest() docResult {
  	const name = "CA key at rest"
  	caDir := filepath.Join(datadir.Root(), "ca")
  	keyPath := filepath.Join(caDir, "ca.key")
  	raw, err := os.ReadFile(keyPath)
  	if err != nil {
  		return docResult{name, stWarn, "ca.key not found — run 'sentinel ca init'"}
  	}
  	bak := keyPath + ".plaintext.bak"
  	if _, berr := os.Stat(bak); berr == nil {
  		return docResult{name, stWarn, "encrypted, but a plaintext backup remains — securely delete ca.key.plaintext.bak"}
  	}
  	if crypto.IsEnvelope(raw) {
  		return docResult{name, stOK, "encrypted at rest"}
  	}
  	cfg, _ := settings.Load(datadir.ConfigPath())
  	if cfg != nil && cfg.Crypto.KeyEncryption == "off" {
  		return docResult{name, stWarn, "PLAINTEXT (crypto.key_encryption=off — dev only)"}
  	}
  	return docResult{name, stWarn, "PLAINTEXT — will be encrypted on next 'sentinel serve'"}
  }
  ```
  Add `checkCAKeyAtRest()` to the `results` slice in `runDoctor` (append alongside `checkCA()`).
- [ ] Run `go build ./... && go test ./cmd/ ./internal/clierr/`. Expect PASS.
- [ ] Cross-compile: `$env:GOOS='linux'; go vet ./...; $env:GOOS=''`.
- [ ] Commit:
  - `git add cmd/serve.go cmd/doctor.go internal/clierr/clierr.go internal/ca/ca.go cmd/identity.go`
  - `git commit -m "feat(serve): wire CA sealer, migrate-on-start, doctor check, unseal clierr"`

---

## Task 12 — Threat model + HARDENING-STATUS + full-suite verification

- [ ] Update `docs/security/THREAT-MODEL.md`: mark T8.1, T8.2, T8.4 (mitigated), and T2.3 (mitigated) with a pointer to this plan and the spec.
- [ ] Add the Phase 3.4 entry to `docs/superpowers/HARDENING-STATUS.md`, mirroring the prior entries' format:

```markdown
## Phase 3.4 — Crypto Hardening (2026-06-04)

**Spec:** `docs/superpowers/specs/2026-06-04-crypto-hardening-design.md`
**Plan:** `docs/superpowers/plans/2026-06-04-crypto-hardening.md`
**Spike:** `docs/superpowers/spikes/2026-06-04-ca-key-keystore.md`
**Closes:** T8.1, T8.2 (CA key compromise), T8.4 (revocation), T2.3 (cert lifetime).

Protects the CA private key at rest with envelope encryption and limits the blast
radius of a stale or compromised device cert. A new `internal/security/crypto`
package owns key-at-rest: a random 32-byte DEK encrypts `ca.key` with AES-256-GCM;
the DEK lives in the OS keystore, or — on headless hosts — is wrapped by an
argon2id-derived key from an operator passphrase. The daemon fails closed and
never regenerates the CA.

| What | Detail | Closes |
|---|---|---|
| Envelope encryption | AES-256-GCM over the CA key; DEK in `KeyStore` (`internal/security/crypto`) | T8.1 |
| Tamper + swap detection | GCM auth tag + cert/key public-key match at load | T8.2 |
| Passphrase fallback | argon2id-wrapped DEK in `ca.key.dek` (`passphrase-env`/`-file`) | T8.1 (headless) |
| Plaintext → encrypted migration | in-place, idempotent, `ca.key.plaintext.bak` (0600), abort-safe | — |
| Local revocation | fleet `revoked`/`revoked_at`/`reason` columns; mTLS `VerifyPeer` rejects revoked peers; live-session close | T8.4 |
| Short-lived certs + auto-renew | `CertValidity` (720h) issuance; own-cert auto-renew under `RenewThreshold` (240h) | T2.3 |
| Config block + migration | `CryptoConfig` (schema v4 → v5) | — |
| Audit + doctor | `device.revoked/unrevoked`, `cakey.sealed/unseal_failed`, `cert.autorenew`; `checkCAKeyAtRest` | — |
| CLI | `sentinel revoke`/`unrevoke`; `fleet list` shows revoked | — |

**Posture:** secure-by-default (`key_encryption=keystore`); `off` allowed for dev
with a loud warning. Fail-closed unseal — a wrong key/passphrase aborts startup
with an `internal/clierr` remediation, never a silent CA regeneration.

**Deferred to backlog:** HSM/TPM-backed CA key, OCSP, distributed CRL, automatic
peer-cert renewal (peer certs warn and reuse `sentinel renew`).

**Tests:** `internal/security/crypto/*_test.go` (fake keystore; real-keystore
smoke `//go:build keystore_smoke`), `internal/ca/sealedkey_test.go`,
`internal/ca/validity_test.go`, `internal/fleet/registry_revoke_test.go`,
`pkg/transport/mtls_revoke_test.go`, `internal/settings/settings_crypto_test.go`,
`cmd/revoke_test.go`, `cmd/autorenew_test.go`, `cmd/serve_revoke_test.go`.
`go build`/`vet`/`test`/`golangci-lint` green; linux cross-build verified.
```

- [ ] Run the full verification suite:
  - `go build ./...`
  - `go test ./...`
  - `golangci-lint run --fix ./... --timeout=5m`
  - `$env:GOOS='linux'; go vet ./...; $env:GOOS=''` (cross-compile gate)
  - `go test -tags keystore_smoke ./internal/security/crypto/` (local only; skips if no keystore)
- [ ] Confirm every output is green before claiming completion (superpowers:verification-before-completion: evidence before assertions).
- [ ] Commit:
  - `git add docs/security/THREAT-MODEL.md docs/superpowers/HARDENING-STATUS.md`
  - `git commit -m "docs(security): mark T8.1/T8.2/T8.4/T2.3 mitigated; Phase 3.4 status entry"`

---

## Self-Review Checklist (writing-plans requirement)

- [ ] **Every §11 deliverable maps to a task:** crypto package (T1, T3), ca-through-envelope + match + fail-closed (T4), migration + `.plaintext.bak` (T5), revocation columns + migration (T7), mTLS rejects revoked + live close (T8), revoke/unrevoke CLI + fleet list (T9), short-lived + auto-renew (T10), CryptoConfig v4→v5 (T6), audit events + doctor (T7a, T11), full TDD + cross-build + threat-model + HARDENING-STATUS (T12). Keystore spike (T2) covers the spec's mandated research step.
- [ ] **No placeholders:** scanned for TODO/TBD/"similar to"/"add appropriate" — none in code steps. (Two test bodies in T8c/T9/T10b are intentionally described as setup-mirroring with a single concrete assertion noted; every *production* code step is complete and compiling.)
- [ ] **Name consistency:** `CryptoConfig{KeyEncryption, PassphraseEnv, PassphraseFile, CertValidity=720h, RenewThreshold=240h}` matches the spec §7; four modes `keystore|passphrase-env|passphrase-file|off`; `KeyStore{Get,Set,Delete,Available}` + `ErrNotFound`; `Encrypt(dek,plaintext)`/`Decrypt(dek,envelope)`; `Sealer.Seal/Unseal`; events `device.revoked`/`device.unrevoked`/`cakey.sealed`/`cakey.unseal_failed` (Critical), `cert.autorenew` (Routine); `CurrentConfigVersion` 4→5; `Revoke/Unrevoke/IsRevoked`; `SignDeviceFor`/`ReSignSelf`; `VerifyPeer` hook; `ClassifyCAUnseal`/`KindCAUnseal`.
- [ ] **Spec ambiguities resolved inline:** (a) keystore library choice deferred to the T2 spike with explicit accept/reject criteria; (b) the mTLS server config had no existing `VerifyPeerCertificate` — T8 adds the `VerifyPeer` seam; (c) live-connection close uses an in-band heartbeat `IsRevoked` check (preferred when session owner tracking is absent) rather than a separate sweeper.
