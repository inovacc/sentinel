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
	ModeKeystore       = "keystore"
	ModePassphraseEnv  = "passphrase-env"
	ModePassphraseFile = "passphrase-file"
	ModeOff            = "off"
)

// The default service/account names under which the DEK is stored.
const (
	keystoreService = "sentinel-ca"
	keystoreAccount = "dek"
)

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
