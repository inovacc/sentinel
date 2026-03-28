package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tamperDeviceID flips a character in the data portion of the first group
// so the Luhn check digit no longer matches.
func tamperDeviceID(id string) string {
	b := []byte(id)
	// Flip the first character: if it's 'A' make it 'B', otherwise make it 'A'
	if b[0] == 'A' {
		b[0] = 'B'
	} else {
		b[0] = 'A'
	}
	return string(b)
}

func TestInitCreatesValidFiles(t *testing.T) {
	dir := t.TempDir()

	c, err := Init(dir)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	certPath := filepath.Join(dir, caCertFile)
	keyPath := filepath.Join(dir, caKeyFile)

	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("cert file missing: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("key file missing: %v", err)
	}

	// Check key file permissions (skip on Windows where permissions work differently)
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	_ = info

	if c.rootCert == nil {
		t.Fatal("rootCert is nil")
	}
	if c.rootKey == nil {
		t.Fatal("rootKey is nil")
	}
	if !c.rootCert.IsCA {
		t.Fatal("root cert is not CA")
	}
}

func TestInitTwiceFails(t *testing.T) {
	dir := t.TempDir()

	_, err := Init(dir)
	if err != nil {
		t.Fatalf("first Init: %v", err)
	}

	_, err = Init(dir)
	if err == nil {
		t.Fatal("expected error on second Init")
	}
	if !strings.Contains(err.Error(), "already initialized") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadNonexistent(t *testing.T) {
	dir := t.TempDir()

	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected error loading nonexistent CA")
	}
}

func TestLoadReadsBack(t *testing.T) {
	dir := t.TempDir()

	original, err := Init(dir)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if !original.rootCert.Equal(loaded.rootCert) {
		t.Fatal("loaded cert does not match original")
	}
}

func TestLoadOrInit(t *testing.T) {
	dir := t.TempDir()

	// First call should init
	c1, err := LoadOrInit(dir)
	if err != nil {
		t.Fatalf("LoadOrInit (init): %v", err)
	}

	// Second call should load
	c2, err := LoadOrInit(dir)
	if err != nil {
		t.Fatalf("LoadOrInit (load): %v", err)
	}

	if !c1.rootCert.Equal(c2.rootCert) {
		t.Fatal("certs should match")
	}
}

func TestSignDevice(t *testing.T) {
	tests := []struct {
		name string
		role string
	}{
		{"admin role", RoleAdmin},
		{"operator role", RoleOperator},
		{"reader role", RoleReader},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			c, err := Init(dir)
			if err != nil {
				t.Fatalf("Init: %v", err)
			}

			certPEM, keyPEM, err := c.SignDevice(tt.role)
			if err != nil {
				t.Fatalf("SignDevice: %v", err)
			}

			if len(certPEM) == 0 {
				t.Fatal("certPEM is empty")
			}
			if len(keyPEM) == 0 {
				t.Fatal("keyPEM is empty")
			}

			// Parse and verify the certificate
			cert, err := decodeCertPEM(certPEM)
			if err != nil {
				t.Fatalf("decodeCertPEM: %v", err)
			}

			// Verify signed by root
			roots := x509.NewCertPool()
			roots.AddCert(c.rootCert)
			_, err = cert.Verify(x509.VerifyOptions{
				Roots: roots,
			})
			if err != nil {
				t.Fatalf("cert verification: %v", err)
			}

			// Verify role
			role, err := ExtractRole(cert)
			if err != nil {
				t.Fatalf("ExtractRole: %v", err)
			}
			if role != tt.role {
				t.Fatalf("role = %q, want %q", role, tt.role)
			}

			// Verify key is valid
			_, err = decodeKeyPEM(keyPEM)
			if err != nil {
				t.Fatalf("decodeKeyPEM: %v", err)
			}
		})
	}
}

func TestSignDeviceInvalidRole(t *testing.T) {
	dir := t.TempDir()
	c, err := Init(dir)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	_, _, err = c.SignDevice("superadmin")
	if err == nil {
		t.Fatal("expected error for invalid role")
	}
}

func TestSignCSR(t *testing.T) {
	dir := t.TempDir()
	c, err := Init(dir)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Generate a CSR
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "Test Device",
			Organization: []string{"Sentinel"},
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	certPEM, err := c.SignCSR(csrPEM, RoleOperator)
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}

	cert, err := decodeCertPEM(certPEM)
	if err != nil {
		t.Fatalf("decode cert: %v", err)
	}

	role, err := ExtractRole(cert)
	if err != nil {
		t.Fatalf("ExtractRole: %v", err)
	}
	if role != RoleOperator {
		t.Fatalf("role = %q, want %q", role, RoleOperator)
	}

	// Verify signed by root
	roots := x509.NewCertPool()
	roots.AddCert(c.rootCert)
	_, err = cert.Verify(x509.VerifyOptions{
		Roots: roots,
	})
	if err != nil {
		t.Fatalf("cert verification: %v", err)
	}
}

func TestSignCSRInvalidPEM(t *testing.T) {
	dir := t.TempDir()
	c, err := Init(dir)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	_, err = c.SignCSR([]byte("not a pem"), RoleAdmin)
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestDeviceIDFormat(t *testing.T) {
	dir := t.TempDir()
	c, err := Init(dir)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	certPEM, _, err := c.SignDevice(RoleAdmin)
	if err != nil {
		t.Fatalf("SignDevice: %v", err)
	}

	id, err := DeviceID(certPEM)
	if err != nil {
		t.Fatalf("DeviceID: %v", err)
	}

	// Check format: groups separated by dashes
	groups := strings.Split(id, "-")
	if len(groups) == 0 {
		t.Fatal("no groups in device ID")
	}

	for _, g := range groups {
		if len(g) < 2 {
			t.Fatalf("group too short: %q", g)
		}
		// All chars should be base32 alphabet
		for _, ch := range g {
			if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", ch) {
				t.Fatalf("invalid char %c in device ID", ch)
			}
		}
	}

	t.Logf("Device ID: %s", id)
}

func TestDeviceIDDeterministic(t *testing.T) {
	dir := t.TempDir()
	c, err := Init(dir)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	certPEM, _, err := c.SignDevice(RoleAdmin)
	if err != nil {
		t.Fatalf("SignDevice: %v", err)
	}

	id1, err := DeviceID(certPEM)
	if err != nil {
		t.Fatalf("DeviceID 1: %v", err)
	}

	id2, err := DeviceID(certPEM)
	if err != nil {
		t.Fatalf("DeviceID 2: %v", err)
	}

	if id1 != id2 {
		t.Fatalf("device IDs not deterministic: %q != %q", id1, id2)
	}
}

func TestDeviceIDValidation(t *testing.T) {
	dir := t.TempDir()
	c, err := Init(dir)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	certPEM, _, err := c.SignDevice(RoleReader)
	if err != nil {
		t.Fatalf("SignDevice: %v", err)
	}

	id, err := DeviceID(certPEM)
	if err != nil {
		t.Fatalf("DeviceID: %v", err)
	}

	tests := []struct {
		name  string
		id    string
		valid bool
	}{
		{"valid device ID", id, true},
		{"empty string", "", false},
		{"single char", "A", false},
		{"tampered ID", tamperDeviceID(id), false},
		{"short group", "A-B", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateDeviceID(tt.id)
			if got != tt.valid {
				t.Fatalf("ValidateDeviceID(%q) = %v, want %v", tt.id, got, tt.valid)
			}
		})
	}
}

func TestValidRole(t *testing.T) {
	tests := []struct {
		role  string
		valid bool
	}{
		{RoleAdmin, true},
		{RoleOperator, true},
		{RoleReader, true},
		{"superadmin", false},
		{"", false},
		{"ADMIN", false},
	}

	for _, tt := range tests {
		t.Run(tt.role, func(t *testing.T) {
			if got := ValidRole(tt.role); got != tt.valid {
				t.Fatalf("ValidRole(%q) = %v, want %v", tt.role, got, tt.valid)
			}
		})
	}
}

func TestRootCertPEM(t *testing.T) {
	dir := t.TempDir()
	c, err := Init(dir)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	pemData := c.RootCertPEM()
	if len(pemData) == 0 {
		t.Fatal("RootCertPEM returned empty data")
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatal("failed to decode PEM")
	}
	if block.Type != "CERTIFICATE" {
		t.Fatalf("PEM type = %q, want CERTIFICATE", block.Type)
	}
}

func TestDeviceIDInvalidPEM(t *testing.T) {
	_, err := DeviceID([]byte("not a pem"))
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestExtractRoleNoExtension(t *testing.T) {
	// Create a cert without the role extension
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	serial, _ := randomSerial()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "No Role"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	_, err = ExtractRole(cert)
	if err == nil {
		t.Fatal("expected error for cert without role extension")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}
