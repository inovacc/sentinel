//go:build darwin

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

// Available probes the macOS Keychain with a benign round-trip. Keychain is
// present on all macOS installs, but a sandboxed or headless host may deny
// access, in which case callers fall back to the passphrase mode.
func (osKeyStore) Available() bool { return probeKeystore(osKeyStore{}) }
