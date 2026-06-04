//go:build !windows && !linux && !darwin

package crypto

type osKeyStore struct{}

func newOSKeyStore() KeyStore                        { return osKeyStore{} }
func (osKeyStore) Get(string, string) ([]byte, error) { return nil, ErrNotFound }
func (osKeyStore) Set(string, string, []byte) error   { return ErrNotFound }
func (osKeyStore) Delete(string, string) error        { return nil }
func (osKeyStore) Available() bool                    { return false }
