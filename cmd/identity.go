package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/inovacc/sentinel/internal/ca"
	"github.com/inovacc/sentinel/internal/datadir"
)

// ensureIdentity creates the CA and an admin device certificate if they do not
// already exist, so `serve` works on a fresh machine without a separate
// `ca init`. It returns whether it initialized anything. It is idempotent: when
// both the CA and device cert are present it does nothing.
func ensureIdentity() (created bool, err error) {
	caDir, err := datadir.CADir()
	if err != nil {
		return false, fmt.Errorf("ca dir: %w", err)
	}
	certDir, err := datadir.CertDir()
	if err != nil {
		return false, fmt.Errorf("cert dir: %w", err)
	}

	_, caErr := os.Stat(filepath.Join(caDir, "ca.crt"))
	_, devErr := os.Stat(filepath.Join(certDir, "device.crt"))
	if caErr == nil && devErr == nil {
		return false, nil
	}

	authority, err := ca.LoadOrInit(caDir)
	if err != nil {
		return false, fmt.Errorf("init CA: %w", err)
	}
	certPEM, keyPEM, err := authority.SignDevice(ca.RoleAdmin)
	if err != nil {
		return false, fmt.Errorf("sign device cert: %w", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "device.crt"), certPEM, 0o644); err != nil {
		return false, fmt.Errorf("write device cert: %w", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "device.key"), keyPEM, 0o600); err != nil {
		return false, fmt.Errorf("write device key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "ca.crt"), authority.RootCertPEM(), 0o644); err != nil {
		return false, fmt.Errorf("write CA cert: %w", err)
	}
	return true, nil
}
