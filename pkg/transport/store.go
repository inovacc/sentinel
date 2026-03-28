package transport

import (
	"fmt"
	"os"
	"path/filepath"
)

// CertStore persists bootstrap and mTLS certificates to disk.
// It manages the transition from bootstrap-only to mTLS-ready state.
type CertStore struct {
	dir string
}

// File layout:
//   bootstrap.crt  - self-signed bootstrap certificate
//   bootstrap.key  - bootstrap private key
//   device.crt     - CA-signed device certificate (after bootstrap)
//   device.key     - device private key (after bootstrap)
//   ca.crt         - fleet CA certificate (received during bootstrap)

const (
	fileBootstrapCert = "bootstrap.crt"
	fileBootstrapKey  = "bootstrap.key"
	fileDeviceCert    = "device.crt"
	fileDeviceKey     = "device.key"
	fileCACert        = "ca.crt"
)

// NewCertStore creates a certificate store at the given directory.
func NewCertStore(dir string) (*CertStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("certstore: create dir: %w", err)
	}
	return &CertStore{dir: dir}, nil
}

// HasBootstrap returns true if bootstrap certificates exist.
func (s *CertStore) HasBootstrap() bool {
	_, err1 := os.Stat(filepath.Join(s.dir, fileBootstrapCert))
	_, err2 := os.Stat(filepath.Join(s.dir, fileBootstrapKey))
	return err1 == nil && err2 == nil
}

// HasMTLS returns true if CA-signed device certificates exist.
func (s *CertStore) HasMTLS() bool {
	_, err1 := os.Stat(filepath.Join(s.dir, fileDeviceCert))
	_, err2 := os.Stat(filepath.Join(s.dir, fileDeviceKey))
	_, err3 := os.Stat(filepath.Join(s.dir, fileCACert))
	return err1 == nil && err2 == nil && err3 == nil
}

// SaveBootstrap writes the bootstrap identity to disk.
func (s *CertStore) SaveBootstrap(certPEM, keyPEM []byte) error {
	if err := os.WriteFile(filepath.Join(s.dir, fileBootstrapCert), certPEM, 0o644); err != nil {
		return fmt.Errorf("certstore: write bootstrap cert: %w", err)
	}
	if err := os.WriteFile(filepath.Join(s.dir, fileBootstrapKey), keyPEM, 0o600); err != nil {
		return fmt.Errorf("certstore: write bootstrap key: %w", err)
	}
	return nil
}

// LoadBootstrap reads the bootstrap identity from disk.
func (s *CertStore) LoadBootstrap() (certPEM, keyPEM []byte, err error) {
	certPEM, err = os.ReadFile(filepath.Join(s.dir, fileBootstrapCert))
	if err != nil {
		return nil, nil, fmt.Errorf("certstore: read bootstrap cert: %w", err)
	}
	keyPEM, err = os.ReadFile(filepath.Join(s.dir, fileBootstrapKey))
	if err != nil {
		return nil, nil, fmt.Errorf("certstore: read bootstrap key: %w", err)
	}
	return certPEM, keyPEM, nil
}

// SaveMTLS writes the CA-signed device certificates and CA cert to disk.
func (s *CertStore) SaveMTLS(deviceCertPEM, deviceKeyPEM, caCertPEM []byte) error {
	if err := os.WriteFile(filepath.Join(s.dir, fileDeviceCert), deviceCertPEM, 0o644); err != nil {
		return fmt.Errorf("certstore: write device cert: %w", err)
	}
	if err := os.WriteFile(filepath.Join(s.dir, fileDeviceKey), deviceKeyPEM, 0o600); err != nil {
		return fmt.Errorf("certstore: write device key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(s.dir, fileCACert), caCertPEM, 0o644); err != nil {
		return fmt.Errorf("certstore: write CA cert: %w", err)
	}
	return nil
}

// LoadMTLS reads the CA-signed device certificates and CA cert from disk.
func (s *CertStore) LoadMTLS() (deviceCertPEM, deviceKeyPEM, caCertPEM []byte, err error) {
	deviceCertPEM, err = os.ReadFile(filepath.Join(s.dir, fileDeviceCert))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("certstore: read device cert: %w", err)
	}
	deviceKeyPEM, err = os.ReadFile(filepath.Join(s.dir, fileDeviceKey))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("certstore: read device key: %w", err)
	}
	caCertPEM, err = os.ReadFile(filepath.Join(s.dir, fileCACert))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("certstore: read CA cert: %w", err)
	}
	return deviceCertPEM, deviceKeyPEM, caCertPEM, nil
}

// ClearBootstrap removes bootstrap certificates (after successful mTLS transition).
func (s *CertStore) ClearBootstrap() error {
	_ = os.Remove(filepath.Join(s.dir, fileBootstrapCert))
	_ = os.Remove(filepath.Join(s.dir, fileBootstrapKey))
	return nil
}

// NeedsRenewal checks if the stored device certificate is within the renewal window.
// Returns true if the cert expires within the given number of days.
func (s *CertStore) NeedsRenewal(withinDays int) (bool, error) {
	certPEM, err := os.ReadFile(filepath.Join(s.dir, fileDeviceCert))
	if err != nil {
		return false, fmt.Errorf("certstore: read device cert: %w", err)
	}

	cert, err := decodeCertFromPEM(certPEM)
	if err != nil {
		return false, fmt.Errorf("certstore: parse device cert: %w", err)
	}

	// Check if certificate expires within the window.
	expiresIn := cert.NotAfter.Sub(timeNow())
	threshold := daysToDuration(withinDays)

	return expiresIn <= threshold, nil
}

// Dir returns the store directory path.
func (s *CertStore) Dir() string {
	return s.dir
}
