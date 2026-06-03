package ca

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"testing"
)

func TestFingerprintMatchesSHA256OfDER(t *testing.T) {
	dir := t.TempDir()
	c, err := Init(dir)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	certPEM, _, err := c.SignDevice(RoleOperator)
	if err != nil {
		t.Fatalf("SignDevice: %v", err)
	}

	got, err := Fingerprint(certPEM)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	sum := sha256.Sum256(block.Bytes)
	want := "sha256:" + hex.EncodeToString(sum[:])
	if got != want {
		t.Fatalf("Fingerprint = %q, want %q", got, want)
	}
}

func TestFingerprintDeterministic(t *testing.T) {
	dir := t.TempDir()
	c, err := Init(dir)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	certPEM, _, err := c.SignDevice(RoleReader)
	if err != nil {
		t.Fatalf("SignDevice: %v", err)
	}

	a, err := Fingerprint(certPEM)
	if err != nil {
		t.Fatalf("Fingerprint a: %v", err)
	}
	b, err := Fingerprint(certPEM)
	if err != nil {
		t.Fatalf("Fingerprint b: %v", err)
	}
	if a != b {
		t.Fatalf("non-deterministic: %q != %q", a, b)
	}
}

func TestFingerprintDistinctCerts(t *testing.T) {
	dir := t.TempDir()
	c, err := Init(dir)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	cert1, _, err := c.SignDevice(RoleAdmin)
	if err != nil {
		t.Fatalf("SignDevice 1: %v", err)
	}
	cert2, _, err := c.SignDevice(RoleAdmin)
	if err != nil {
		t.Fatalf("SignDevice 2: %v", err)
	}

	fp1, _ := Fingerprint(cert1)
	fp2, _ := Fingerprint(cert2)
	if fp1 == fp2 {
		t.Fatalf("distinct certs produced identical fingerprint %q", fp1)
	}
}

func TestFingerprintInvalidPEM(t *testing.T) {
	if _, err := Fingerprint([]byte("not a pem")); err == nil {
		t.Fatal("expected error for invalid PEM, got nil")
	}
	if _, err := Fingerprint(nil); err == nil {
		t.Fatal("expected error for nil PEM, got nil")
	}
}
