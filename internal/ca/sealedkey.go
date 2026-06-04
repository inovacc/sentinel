package ca

import (
	"crypto/ecdsa"
	"fmt"
	"os"
	"path/filepath"

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
