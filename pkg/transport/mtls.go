package transport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
)

// MTLSConfig holds the configuration for mutual TLS connections.
type MTLSConfig struct {
	// CertPEM is the CA-signed device certificate.
	CertPEM []byte
	// KeyPEM is the device private key.
	KeyPEM []byte
	// CACertPEM is the CA certificate for verifying peers.
	CACertPEM []byte
}

// MTLSDialer creates outbound mTLS connections to peers.
type MTLSDialer struct {
	tlsConfig *tls.Config
}

// NewMTLSDialer creates a dialer configured for mutual TLS.
func NewMTLSDialer(cfg MTLSConfig) (*MTLSDialer, error) {
	cert, err := tls.X509KeyPair(cfg.CertPEM, cfg.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("mtls: load keypair: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(cfg.CACertPEM) {
		return nil, fmt.Errorf("mtls: failed to parse CA certificate")
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	}

	return &MTLSDialer{tlsConfig: tlsCfg}, nil
}

// Dial connects to a peer using mTLS. The serverName should match the
// certificate's CN or SAN.
func (d *MTLSDialer) Dial(addr string) (net.Conn, error) {
	conn, err := tls.Dial("tcp", addr, d.tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("mtls: dial %s: %w", addr, err)
	}
	return conn, nil
}

// DialInsecure connects using mTLS but skips server name verification.
// Use only when connecting to peers by IP address where server name is unknown.
func (d *MTLSDialer) DialInsecure(addr string) (net.Conn, error) {
	cfg := d.tlsConfig.Clone()
	cfg.InsecureSkipVerify = true
	// Still verify the CA chain manually after connection.
	cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("mtls: no peer certificate")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("mtls: parse peer cert: %w", err)
		}
		_, err = cert.Verify(x509.VerifyOptions{Roots: d.tlsConfig.RootCAs})
		if err != nil {
			return fmt.Errorf("mtls: peer cert not signed by CA: %w", err)
		}
		return nil
	}

	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("mtls: dial %s: %w", addr, err)
	}
	return conn, nil
}

// TLSConfig returns the underlying TLS config for use with gRPC credentials.
func (d *MTLSDialer) TLSConfig() *tls.Config {
	return d.tlsConfig.Clone()
}

// NewMTLSServerConfig creates a TLS config suitable for a server requiring mTLS.
func NewMTLSServerConfig(cfg MTLSConfig) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(cfg.CertPEM, cfg.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("mtls: load server keypair: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(cfg.CACertPEM) {
		return nil, fmt.Errorf("mtls: failed to parse CA certificate")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// NewMTLSListener creates a TLS listener that requires client certificates.
func NewMTLSListener(addr string, cfg MTLSConfig) (net.Listener, error) {
	tlsCfg, err := NewMTLSServerConfig(cfg)
	if err != nil {
		return nil, err
	}

	lis, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("mtls: listen %s: %w", addr, err)
	}

	return lis, nil
}
