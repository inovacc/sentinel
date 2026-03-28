package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/inovacc/sentinel/internal/ca"
)

// BootstrapServer handles incoming bootstrap connections on the Syncthing-key port.
// It implements the server side of the certificate exchange protocol.
type BootstrapServer struct {
	manager  *Manager
	logger   *slog.Logger
	version  string
	hostname string
}

// NewBootstrapServer creates a bootstrap server tied to a transport manager.
func NewBootstrapServer(m *Manager, version string) *BootstrapServer {
	hostname, _ := os.Hostname()
	return &BootstrapServer{
		manager:  m,
		logger:   m.logger.With("component", "bootstrap-server"),
		version:  version,
		hostname: hostname,
	}
}

// Serve accepts and handles bootstrap connections until the context is cancelled
// or the listener is closed.
func (bs *BootstrapServer) Serve(ctx context.Context) error {
	lis := bs.manager.BootstrapListener()
	if lis == nil {
		return fmt.Errorf("bootstrap: no listener available")
	}

	for {
		conn, err := lis.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				// Listener closed (transition happened).
				bs.logger.Info("bootstrap: listener closed")
				return nil
			}
		}

		go bs.handleConn(ctx, conn)
	}
}

// handleConn processes a single bootstrap connection.
func (bs *BootstrapServer) handleConn(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()

	// Set deadline for the entire bootstrap handshake.
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		bs.logger.Error("bootstrap: set deadline", "error", err)
		return
	}

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		bs.logger.Error("bootstrap: connection is not TLS")
		return
	}

	// Complete TLS handshake to get peer certificate.
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		bs.logger.Error("bootstrap: TLS handshake failed", "error", err)
		return
	}

	// Extract peer's device ID from their self-signed certificate.
	peerCerts := tlsConn.ConnectionState().PeerCertificates
	var peerDeviceID string
	var peerCertPEM []byte
	if len(peerCerts) > 0 {
		peerCertPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: peerCerts[0].Raw,
		})
		var err error
		peerDeviceID, err = ca.DeviceID(peerCertPEM)
		if err != nil {
			bs.logger.Error("bootstrap: compute peer device ID", "error", err)
			return
		}
		bs.logger.Info("bootstrap: peer connected", "device_id", peerDeviceID, "addr", conn.RemoteAddr())
	}

	// --- Step 1: Exchange Hello ---
	// Use bootstrap device ID (matches the self-signed TLS cert on this port).
	hello := HelloMessage{
		DeviceID:  bs.manager.BootstrapDeviceID(),
		Hostname:  bs.hostname,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		Version:   bs.version,
		HasCA:     bs.manager.cfg.CA != nil,
		HasMTLS:   bs.manager.hasMTLSCerts(),
	}

	if err := writeMessage(conn, MsgHello, hello); err != nil {
		bs.logger.Error("bootstrap: send hello", "error", err)
		return
	}

	peerHello, err := readTypedMessage[HelloMessage](conn, MsgHello)
	if err != nil {
		bs.logger.Error("bootstrap: read peer hello", "error", err)
		return
	}

	bs.logger.Info("bootstrap: peer hello received",
		"peer_device_id", peerHello.DeviceID,
		"peer_hostname", peerHello.Hostname,
		"peer_os", peerHello.OS,
		"peer_role", peerHello.RequestedRole)

	// Verify the hello device ID matches the TLS certificate.
	if peerDeviceID != "" && peerHello.DeviceID != peerDeviceID {
		bs.logger.Error("bootstrap: device ID mismatch",
			"hello_id", peerHello.DeviceID,
			"cert_id", peerDeviceID)
		_ = writeMessage(conn, MsgError, ErrorMessage{
			Code:    "device_id_mismatch",
			Message: "hello device ID does not match TLS certificate",
		})
		return
	}

	// --- Step 2: Peer acceptance callback ---
	if bs.manager.cfg.OnPeerAccepted != nil {
		accepted, err := bs.manager.cfg.OnPeerAccepted(peerHello.DeviceID, peerCertPEM, peerHello.RequestedRole)
		if err != nil || !accepted {
			reason := "peer rejected by policy"
			if err != nil {
				reason = err.Error()
			}
			bs.logger.Info("bootstrap: peer rejected", "device_id", peerHello.DeviceID, "reason", reason)
			_ = writeMessage(conn, MsgReject, RejectMessage{Reason: reason})
			return
		}
	}

	// --- Step 3: Certificate exchange ---
	// If we have a CA, we can sign the peer's certificate.
	if bs.manager.cfg.CA == nil {
		// No CA: we need to request signing from the peer.
		bs.logger.Info("bootstrap: no local CA, requesting cert from peer")
		if err := bs.requestCertFromPeer(conn, peerHello); err != nil {
			bs.logger.Error("bootstrap: cert request failed", "error", err)
			return
		}
	} else {
		// We have a CA: sign the peer's cert and send ours.
		bs.logger.Info("bootstrap: signing peer certificate")
		if err := bs.signAndExchangeCerts(conn, peerHello, peerCertPEM); err != nil {
			bs.logger.Error("bootstrap: cert exchange failed", "error", err)
			return
		}
	}

	// --- Step 4: Send complete ---
	_ = writeMessage(conn, MsgComplete, CompleteMessage{
		MTLSAddr: bs.manager.cfg.MTLSAddr,
		DeviceID: bs.manager.DeviceID(),
	})

	// Record trusted peer.
	bs.manager.AddTrustedPeer(peerHello.DeviceID, peerCertPEM)
	bs.logger.Info("bootstrap: handshake complete", "peer_device_id", peerHello.DeviceID)
}

// signAndExchangeCerts sends our CA cert and signs the peer's CSR.
func (bs *BootstrapServer) signAndExchangeCerts(conn net.Conn, peerHello *HelloMessage, peerCertPEM []byte) error {
	// Send our CA cert.
	exchange := CertExchangeMessage{
		CACertPEM: string(bs.manager.cfg.CA.RootCertPEM()),
		MTLSPort:  0, // Will be in Complete message.
	}

	// If we already have a signed device cert, include it.
	if len(bs.manager.cfg.DeviceCertPEM) > 0 {
		exchange.DeviceCertPEM = string(bs.manager.cfg.DeviceCertPEM)
	}

	if err := writeMessage(conn, MsgCertExchange, exchange); err != nil {
		return fmt.Errorf("send cert exchange: %w", err)
	}

	// Wait for the peer's cert request.
	certReq, err := readTypedMessage[CertRequestMessage](conn, MsgCertRequest)
	if err != nil {
		return fmt.Errorf("read cert request: %w", err)
	}

	// Sign the CSR with assigned role.
	role := certReq.RequestedRole
	if !ca.ValidRole(role) {
		role = ca.RoleReader // Default to least privilege.
	}

	signedCert, err := bs.manager.cfg.CA.SignCSR([]byte(certReq.CSRPEM), role)
	if err != nil {
		return fmt.Errorf("sign CSR: %w", err)
	}

	// Send signed cert back.
	resp := CertResponseMessage{
		SignedCertPEM: string(signedCert),
		CACertPEM:    string(bs.manager.cfg.CA.RootCertPEM()),
		AssignedRole: role,
	}

	if err := writeMessage(conn, MsgCertResponse, resp); err != nil {
		return fmt.Errorf("send cert response: %w", err)
	}

	// Send accept.
	return writeMessage(conn, MsgAccept, AcceptMessage{
		DeviceID:     peerHello.DeviceID,
		AssignedRole: role,
	})
}

// requestCertFromPeer asks the peer (who has a CA) to sign our CSR.
func (bs *BootstrapServer) requestCertFromPeer(conn net.Conn, peerHello *HelloMessage) error {
	// Wait for peer's cert exchange (they have CA).
	exchange, err := readTypedMessage[CertExchangeMessage](conn, MsgCertExchange)
	if err != nil {
		return fmt.Errorf("read cert exchange: %w", err)
	}

	// Generate a CSR.
	csrPEM, err := generateCSR(bs.hostname)
	if err != nil {
		return fmt.Errorf("generate CSR: %w", err)
	}

	// Send cert request.
	if err := writeMessage(conn, MsgCertRequest, CertRequestMessage{
		CSRPEM:        string(csrPEM),
		RequestedRole: ca.RoleOperator,
	}); err != nil {
		return fmt.Errorf("send cert request: %w", err)
	}

	// Wait for signed cert.
	certResp, err := readTypedMessage[CertResponseMessage](conn, MsgCertResponse)
	if err != nil {
		return fmt.Errorf("read cert response: %w", err)
	}

	bs.logger.Info("bootstrap: received signed certificate",
		"role", certResp.AssignedRole,
		"has_ca", exchange.CACertPEM != "")

	// Wait for accept.
	_, err = readTypedMessage[AcceptMessage](conn, MsgAccept)
	if err != nil {
		return fmt.Errorf("read accept: %w", err)
	}

	return nil
}

// BootstrapClient connects to a bootstrap server and completes the handshake.
type BootstrapClient struct {
	manager  *Manager
	logger   *slog.Logger
	version  string
	hostname string
}

// NewBootstrapClient creates a bootstrap client tied to a transport manager.
func NewBootstrapClient(m *Manager, version string) *BootstrapClient {
	hostname, _ := os.Hostname()
	return &BootstrapClient{
		manager:  m,
		logger:   m.logger.With("component", "bootstrap-client"),
		version:  version,
		hostname: hostname,
	}
}

// BootstrapResult contains the result of a successful bootstrap handshake.
type BootstrapResult struct {
	// PeerDeviceID is the server's device ID.
	PeerDeviceID string
	// SignedCertPEM is our CA-signed certificate (if we got one).
	SignedCertPEM []byte
	// CACertPEM is the fleet CA certificate.
	CACertPEM []byte
	// AssignedRole is the role assigned to us.
	AssignedRole string
	// MTLSAddr is the address to reconnect to using mTLS.
	MTLSAddr string
}

// Connect performs the bootstrap handshake with a remote server.
func (bc *BootstrapClient) Connect(ctx context.Context, addr string, requestedRole string) (*BootstrapResult, error) {
	// Connect with self-signed TLS.
	cert, err := tls.X509KeyPair(bc.manager.cfg.BootstrapCertPEM, bc.manager.cfg.BootstrapKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: load client keypair: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true, // Bootstrap uses self-signed certs; we verify via device ID.
		MinVersion:         tls.VersionTLS13,
	}

	dialer := &tls.Dialer{Config: tlsCfg}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return nil, fmt.Errorf("bootstrap: set deadline: %w", err)
	}

	// Verify server's device ID from TLS cert.
	tlsConn := conn.(*tls.Conn)
	serverCerts := tlsConn.ConnectionState().PeerCertificates
	var serverDeviceID string
	if len(serverCerts) > 0 {
		serverCertPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: serverCerts[0].Raw,
		})
		serverDeviceID, err = ca.DeviceID(serverCertPEM)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: compute server device ID: %w", err)
		}
		bc.logger.Info("bootstrap: connected to server", "device_id", serverDeviceID, "addr", addr)
	}

	// --- Step 1: Exchange Hello ---
	// Read server's hello first.
	serverHello, err := readTypedMessage[HelloMessage](conn, MsgHello)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: read server hello: %w", err)
	}

	// Verify device ID matches.
	if serverDeviceID != "" && serverHello.DeviceID != serverDeviceID {
		return nil, fmt.Errorf("bootstrap: server device ID mismatch: hello=%s cert=%s",
			serverHello.DeviceID, serverDeviceID)
	}

	// Send our hello.
	hello := HelloMessage{
		DeviceID:      bc.manager.DeviceID(),
		Hostname:      bc.hostname,
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		Version:       bc.version,
		HasCA:         bc.manager.cfg.CA != nil,
		HasMTLS:       bc.manager.hasMTLSCerts(),
		RequestedRole: requestedRole,
	}

	if err := writeMessage(conn, MsgHello, hello); err != nil {
		return nil, fmt.Errorf("bootstrap: send hello: %w", err)
	}

	// --- Step 2: Check for rejection ---
	env, err := readEnvelope(conn)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: read response: %w", err)
	}

	if env.Type == MsgReject {
		var reject RejectMessage
		if err := env.DecodePayload(&reject); err != nil {
			return nil, fmt.Errorf("bootstrap: decode reject: %w", err)
		}
		return nil, fmt.Errorf("bootstrap: rejected by server: %s", reject.Reason)
	}

	// --- Step 3: Certificate exchange ---
	result := &BootstrapResult{
		PeerDeviceID: serverHello.DeviceID,
	}

	if env.Type == MsgCertExchange {
		// Server has CA, it sent us certs.
		var exchange CertExchangeMessage
		if err := env.DecodePayload(&exchange); err != nil {
			return nil, fmt.Errorf("bootstrap: decode cert exchange: %w", err)
		}

		result.CACertPEM = []byte(exchange.CACertPEM)

		// Generate CSR and request signing.
		csrPEM, keyPEM, err := generateCSRWithKey(bc.hostname)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: generate CSR: %w", err)
		}

		if err := writeMessage(conn, MsgCertRequest, CertRequestMessage{
			CSRPEM:        string(csrPEM),
			RequestedRole: requestedRole,
		}); err != nil {
			return nil, fmt.Errorf("bootstrap: send cert request: %w", err)
		}

		// Read signed cert.
		certResp, err := readTypedMessage[CertResponseMessage](conn, MsgCertResponse)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: read cert response: %w", err)
		}

		result.SignedCertPEM = []byte(certResp.SignedCertPEM)
		result.CACertPEM = []byte(certResp.CACertPEM)
		result.AssignedRole = certResp.AssignedRole

		// Read accept.
		_, err = readTypedMessage[AcceptMessage](conn, MsgAccept)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: read accept: %w", err)
		}

		// Store the key for mTLS transition.
		bc.manager.cfg.DeviceCertPEM = result.SignedCertPEM
		bc.manager.cfg.DeviceKeyPEM = keyPEM

		bc.logger.Info("bootstrap: received signed certificate",
			"role", result.AssignedRole)
	}

	// --- Step 4: Read complete ---
	complete, err := readTypedMessage[CompleteMessage](conn, MsgComplete)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: read complete: %w", err)
	}

	result.MTLSAddr = complete.MTLSAddr
	bc.logger.Info("bootstrap: handshake complete",
		"server_device_id", serverHello.DeviceID,
		"mtls_addr", result.MTLSAddr)

	return result, nil
}

// --- Wire format helpers ---

// writeMessage encodes and sends a protocol message.
func writeMessage(conn net.Conn, msgType MessageType, payload any) error {
	env, err := NewEnvelope(msgType, payload)
	if err != nil {
		return err
	}
	data, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("transport: marshal envelope: %w", err)
	}

	// Length-prefixed: 4 bytes big-endian length + JSON.
	length := uint32(len(data))
	header := []byte{
		byte(length >> 24),
		byte(length >> 16),
		byte(length >> 8),
		byte(length),
	}

	if _, err := conn.Write(header); err != nil {
		return fmt.Errorf("transport: write header: %w", err)
	}
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("transport: write payload: %w", err)
	}
	return nil
}

// readEnvelope reads a length-prefixed envelope from the connection.
func readEnvelope(conn net.Conn) (*Envelope, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("transport: read header: %w", err)
	}

	length := uint32(header[0])<<24 | uint32(header[1])<<16 | uint32(header[2])<<8 | uint32(header[3])

	// Sanity check: max 10MB.
	if length > 10*1024*1024 {
		return nil, fmt.Errorf("transport: message too large: %d bytes", length)
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, fmt.Errorf("transport: read payload: %w", err)
	}

	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("transport: unmarshal envelope: %w", err)
	}

	return &env, nil
}

// readTypedMessage reads an envelope and decodes its payload as the expected type.
func readTypedMessage[T any](conn net.Conn, expected MessageType) (*T, error) {
	env, err := readEnvelope(conn)
	if err != nil {
		return nil, err
	}

	// Check for error messages.
	if env.Type == MsgError {
		var errMsg ErrorMessage
		if decErr := env.DecodePayload(&errMsg); decErr == nil {
			return nil, fmt.Errorf("transport: remote error [%s]: %s", errMsg.Code, errMsg.Message)
		}
		return nil, fmt.Errorf("transport: remote error (undecoded)")
	}

	if env.Type != expected {
		return nil, fmt.Errorf("transport: expected %s, got %s", expected, env.Type)
	}

	var msg T
	if err := env.DecodePayload(&msg); err != nil {
		return nil, fmt.Errorf("transport: decode %s: %w", expected, err)
	}

	return &msg, nil
}

// --- Certificate helpers ---

// GenerateBootstrapIdentity creates a self-signed certificate and key for bootstrap.
// The certificate is valid for 24 hours (just long enough for initial pairing).
func GenerateBootstrapIdentity() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("transport: generate bootstrap key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("transport: serial number: %w", err)
	}

	hostname, _ := os.Hostname()
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("sentinel-bootstrap-%s", hostname),
			Organization: []string{"Sentinel Bootstrap"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("transport: create bootstrap cert: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("transport: marshal bootstrap key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// generateCSR creates a CSR for requesting a signed certificate.
func generateCSR(hostname string) (csrPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("transport: generate key: %w", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("sentinel-%s", hostname),
			Organization: []string{"Sentinel"},
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("transport: create CSR: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

// generateCSRWithKey creates a CSR and returns both the CSR PEM and the private key PEM.
func generateCSRWithKey(hostname string) (csrPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("transport: generate key: %w", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("sentinel-%s", hostname),
			Organization: []string{"Sentinel"},
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, nil, fmt.Errorf("transport: create CSR: %w", err)
	}

	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("transport: marshal key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return csrPEM, keyPEM, nil
}
