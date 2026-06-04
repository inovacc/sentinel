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
	LoadDEKFile func() ([]byte, error) // returns nil,nil when absent
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
