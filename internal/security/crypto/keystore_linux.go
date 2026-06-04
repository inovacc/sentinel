//go:build linux

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

// Available probes the Secret Service / kwallet with a benign round-trip. A
// headless Linux host with no D-Bus session returns false, causing the caller
// to fall back to the passphrase mode.
func (osKeyStore) Available() bool { return probeKeystore(osKeyStore{}) }
