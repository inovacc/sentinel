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
