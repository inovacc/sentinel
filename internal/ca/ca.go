package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	sentinelcrypto "github.com/inovacc/sentinel/internal/security/crypto"
)

const (
	caCertFile = "ca.crt"
	caKeyFile  = "ca.key"
)

// CA manages the root certificate authority for the sentinel fleet.
type CA struct {
	rootCert *x509.Certificate
	rootKey  crypto.PrivateKey
	dir      string                   // directory where CA files are stored
	sealer   *sentinelcrypto.Sealer   // seals/unseals rootKey on disk; passthrough by default
}

// Init generates a new root CA with plaintext key-at-rest (backward compatible).
func Init(dir string) (*CA, error) { return InitWithSealer(dir, passthroughSealer()) }

// InitWithSealer generates a new root CA (P-256 ECDSA), saves cert+key to dir,
// sealing the key with sealer. Root cert is valid for 10 years.
// Returns an error if the CA already exists.
func InitWithSealer(dir string, sealer *sentinelcrypto.Sealer) (*CA, error) {
	certPath := filepath.Join(dir, caCertFile)
	keyPath := filepath.Join(dir, caKeyFile)

	if _, err := os.Stat(certPath); err == nil {
		return nil, fmt.Errorf("ca: already initialized at %s", dir)
	}
	if _, err := os.Stat(keyPath); err == nil {
		return nil, fmt.Errorf("ca: key already exists at %s", dir)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ca: generate key: %w", err)
	}

	serialNumber, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("ca: serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Sentinel Root CA",
			Organization: []string{"Sentinel"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("ca: create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("ca: parse certificate: %w", err)
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("ca: create directory: %w", err)
	}

	if err := writeCertPEM(certPath, certDER); err != nil {
		return nil, fmt.Errorf("ca: write cert: %w", err)
	}

	if err := writeKeyPEMSealed(keyPath, key, sealer); err != nil {
		return nil, fmt.Errorf("ca: write key: %w", err)
	}

	return &CA{rootCert: cert, rootKey: key, dir: dir, sealer: sealer}, nil
}

// Load reads an existing CA, plaintext key-at-rest (backward compatible).
func Load(dir string) (*CA, error) { return LoadWithSealer(dir, passthroughSealer()) }

// LoadWithSealer reads an existing CA, unsealing the key with sealer and
// verifying the cert matches the key. It fails closed and never regenerates.
func LoadWithSealer(dir string, sealer *sentinelcrypto.Sealer) (*CA, error) {
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

// LoadOrInit loads if exists, initializes if not.
func LoadOrInit(dir string) (*CA, error) { return LoadOrInitWithSealer(dir, passthroughSealer()) }

// LoadOrInitWithSealer loads if exists, else initializes, both sealed.
func LoadOrInitWithSealer(dir string, sealer *sentinelcrypto.Sealer) (*CA, error) {
	if _, err := os.Stat(filepath.Join(dir, caCertFile)); err == nil {
		return LoadWithSealer(dir, sealer)
	}
	return InitWithSealer(dir, sealer)
}

// SignDevice generates a new device keypair and signs it with the root CA.
// The role is embedded in a custom X.509 extension.
// Device certs are valid for 1 year.
func (c *CA) SignDevice(role string) (certPEM, keyPEM []byte, err error) {
	if !ValidRole(role) {
		return nil, nil, fmt.Errorf("ca: invalid role %q", role)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: generate device key: %w", err)
	}

	serialNumber, err := randomSerial()
	if err != nil {
		return nil, nil, fmt.Errorf("ca: serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Sentinel Device",
			Organization: []string{"Sentinel"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{roleExtension(role)},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, c.rootCert, &key.PublicKey, c.rootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: sign device cert: %w", err)
	}

	certPEM = encodeCertPEM(certDER)
	keyPEM, err = encodeKeyPEM(key)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: encode device key: %w", err)
	}

	return certPEM, keyPEM, nil
}

// SignCSR signs a certificate signing request with the given role.
func (c *CA) SignCSR(csrPEM []byte, role string) ([]byte, error) {
	if !ValidRole(role) {
		return nil, fmt.Errorf("ca: invalid role %q", role)
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("ca: invalid CSR PEM")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parse CSR: %w", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("ca: CSR signature invalid: %w", err)
	}

	serialNumber, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("ca: serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               csr.Subject,
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{roleExtension(role)},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, c.rootCert, csr.PublicKey, c.rootKey)
	if err != nil {
		return nil, fmt.Errorf("ca: sign CSR: %w", err)
	}

	return encodeCertPEM(certDER), nil
}

// RootCertPEM exports the root certificate as PEM.
func (c *CA) RootCertPEM() []byte {
	return encodeCertPEM(c.rootCert.Raw)
}

// --- helpers ---

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func encodeCertPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	})
}

func encodeKeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal ec key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}), nil
}

func decodeCertPEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func decodeKeyPEM(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid key PEM")
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	default:
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not ECDSA")
		}
		return ecKey, nil
	}
}

func writeCertPEM(path string, der []byte) error {
	return os.WriteFile(path, encodeCertPEM(der), 0o644)
}
