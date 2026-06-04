package transport

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
)

// revokeTestPair returns (certPEM, keyPEM, caPEM) all from the same CA so the
// keypair is consistent. Use this instead of calling newTestSetup separately
// for cert and key — independent calls create different CAs.
func revokeTestPair(t *testing.T) (certPEM, keyPEM, caPEM []byte) {
	t.Helper()
	ts := newTestSetup(t)
	return ts.DeviceCert, ts.DeviceKey, ts.CA.RootCertPEM()
}

// testLeafDER returns the raw DER bytes of a CA-signed device leaf certificate.
func testLeafDER(t *testing.T) []byte {
	t.Helper()
	ts := newTestSetup(t)
	block, _ := pem.Decode(ts.DeviceCert)
	if block == nil {
		t.Fatal("testLeafDER: no PEM block in device cert")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("testLeafDER: parse cert: %v", err)
	}
	return cert.Raw
}

func TestServerConfigRejectsRevokedPeer(t *testing.T) {
	revoked := errors.New("revoked")
	certPEM, keyPEM, caPEM := revokeTestPair(t)
	cfg := MTLSConfig{
		CertPEM:    certPEM,
		KeyPEM:     keyPEM,
		CACertPEM:  caPEM,
		VerifyPeer: func(_ *x509.Certificate) error { return revoked },
	}
	tlsCfg, err := NewMTLSServerConfig(cfg)
	if err != nil {
		t.Fatalf("NewMTLSServerConfig: %v", err)
	}
	if tlsCfg.VerifyPeerCertificate == nil {
		t.Fatal("expected VerifyPeerCertificate to be wired when VerifyPeer is set")
	}
	// Feed the hook a valid leaf; it must surface the VerifyPeer error.
	leaf := testLeafDER(t)
	err = tlsCfg.VerifyPeerCertificate([][]byte{leaf}, nil)
	if !errors.Is(err, revoked) {
		t.Fatalf("expected revoked error, got %v", err)
	}
}

func TestServerConfigNilVerifyPeerAllows(t *testing.T) {
	certPEM, keyPEM, caPEM := revokeTestPair(t)
	cfg := MTLSConfig{CertPEM: certPEM, KeyPEM: keyPEM, CACertPEM: caPEM}
	tlsCfg, err := NewMTLSServerConfig(cfg)
	if err != nil {
		t.Fatalf("NewMTLSServerConfig: %v", err)
	}
	if tlsCfg.VerifyPeerCertificate != nil {
		t.Fatal("no VerifyPeer set → no custom verification hook")
	}
}
