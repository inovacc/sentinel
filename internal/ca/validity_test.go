package ca

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestSignDeviceForHonorsValidity(t *testing.T) {
	c, err := Init(t.TempDir())
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	certPEM, _, err := c.SignDeviceFor(RoleReader, 720*time.Hour)
	if err != nil {
		t.Fatalf("SignDeviceFor: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)
	got := cert.NotAfter.Sub(cert.NotBefore)
	// Allow a small slop for the issuance timestamp.
	if got < 719*time.Hour || got > 721*time.Hour {
		t.Fatalf("validity = %v, want ~720h", got)
	}
}

func TestSignDeviceDefaultsToOneYear(t *testing.T) {
	c, _ := Init(t.TempDir())
	certPEM, _, err := c.SignDevice(RoleReader) // unchanged default behavior
	if err != nil {
		t.Fatalf("SignDevice: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)
	got := cert.NotAfter.Sub(cert.NotBefore)
	if got < 364*24*time.Hour {
		t.Fatalf("default validity = %v, want ~1y", got)
	}
}
