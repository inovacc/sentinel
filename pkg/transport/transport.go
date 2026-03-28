// Package transport implements the two-phase connection lifecycle for Sentinel.
//
// Phase 1 - Bootstrap (Syncthing-key port):
//
//	Devices connect using self-signed TLS certificates. They identify each other
//	by Syncthing-style device IDs (SHA-256 of cert → base32 with Luhn checks).
//	During this phase, devices exchange their CA certificate and a signed device
//	certificate. Once exchange completes, the bootstrap listener is shut down.
//
// Phase 2 - mTLS (production port):
//
//	Devices reconnect using CA-signed certificates with mutual TLS verification.
//	The bootstrap port is closed to eliminate attack surface. All subsequent
//	communication uses mTLS exclusively.
//
// Detection: On startup, if valid mTLS certificates already exist, the bootstrap
// phase is skipped entirely and only the mTLS listener starts.
//
// Certificate renewal: A --renew-certs flag can temporarily re-open the bootstrap
// port to exchange updated certificates, then close it again.
package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/inovacc/sentinel/internal/ca"
)

// Phase describes the current transport lifecycle state.
type Phase int

const (
	// PhaseBootstrap is the initial handshake phase using Syncthing-style keys.
	PhaseBootstrap Phase = iota
	// PhaseMTLS is the production phase using mutual TLS.
	PhaseMTLS
	// PhaseRenewing temporarily re-opens bootstrap for certificate renewal.
	PhaseRenewing
)

func (p Phase) String() string {
	switch p {
	case PhaseBootstrap:
		return "bootstrap"
	case PhaseMTLS:
		return "mtls"
	case PhaseRenewing:
		return "renewing"
	default:
		return "unknown"
	}
}

// Config configures the transport manager.
type Config struct {
	// BootstrapAddr is the address for the Syncthing-key bootstrap listener (e.g., ":7399").
	BootstrapAddr string
	// MTLSAddr is the address for the mTLS production listener (e.g., ":7400").
	MTLSAddr string
	// CA is the certificate authority for signing/verifying.
	CA *ca.CA
	// DeviceCertPEM is this device's certificate (CA-signed, if available).
	DeviceCertPEM []byte
	// DeviceKeyPEM is this device's private key.
	DeviceKeyPEM []byte
	// BootstrapCertPEM is the self-signed certificate for bootstrap phase.
	BootstrapCertPEM []byte
	// BootstrapKeyPEM is the private key for bootstrap phase.
	BootstrapKeyPEM []byte
	// OnPeerAccepted is called when a new peer completes bootstrap and is accepted.
	// The callback receives the peer's device ID, certificate, and requested role.
	OnPeerAccepted func(peerID string, peerCert []byte, role string) (accepted bool, err error)
	// Logger for transport events.
	Logger *slog.Logger
	// BootstrapTimeout is the max time to keep bootstrap port open (default 5m).
	BootstrapTimeout time.Duration
}

// Manager orchestrates the two-phase transport lifecycle.
type Manager struct {
	cfg    Config
	logger *slog.Logger

	mu    sync.RWMutex
	phase Phase

	bootstrapListener net.Listener
	mtlsListener      net.Listener

	// deviceID is this device's Syncthing-style ID (from bootstrap cert).
	deviceID string
	// mtlsDeviceID is this device's ID from the CA-signed cert (may differ if renewed).
	mtlsDeviceID string

	// trustedPeers tracks peers that completed bootstrap (device ID → cert PEM).
	trustedPeers map[string][]byte

	cancel context.CancelFunc
	done   chan struct{}
}

// NewManager creates a transport manager. It detects whether mTLS certificates
// are available and sets the initial phase accordingly.
func NewManager(cfg Config) (*Manager, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.BootstrapTimeout == 0 {
		cfg.BootstrapTimeout = 5 * time.Minute
	}

	m := &Manager{
		cfg:          cfg,
		logger:       cfg.Logger,
		trustedPeers: make(map[string][]byte),
		done:         make(chan struct{}),
	}

	// Compute bootstrap device ID.
	if len(cfg.BootstrapCertPEM) > 0 {
		id, err := ca.DeviceID(cfg.BootstrapCertPEM)
		if err != nil {
			return nil, fmt.Errorf("transport: compute bootstrap device ID: %w", err)
		}
		m.deviceID = id
	}

	// Compute mTLS device ID if CA-signed cert is available.
	if len(cfg.DeviceCertPEM) > 0 {
		id, err := ca.DeviceID(cfg.DeviceCertPEM)
		if err != nil {
			return nil, fmt.Errorf("transport: compute mtls device ID: %w", err)
		}
		m.mtlsDeviceID = id
	}

	// Detect phase: if we have valid CA-signed certs, go straight to mTLS.
	if m.hasMTLSCerts() {
		m.phase = PhaseMTLS
		m.logger.Info("transport: mTLS certificates detected, skipping bootstrap",
			"device_id", m.mtlsDeviceID)
	} else {
		m.phase = PhaseBootstrap
		m.logger.Info("transport: no mTLS certificates, starting in bootstrap mode",
			"device_id", m.deviceID)
	}

	return m, nil
}

// Phase returns the current transport phase.
func (m *Manager) Phase() Phase {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.phase
}

// DeviceKeyPEM returns the current device private key PEM.
func (m *Manager) DeviceKeyPEM() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.cfg.DeviceKeyPEM) > 0 {
		return m.cfg.DeviceKeyPEM
	}
	return m.cfg.BootstrapKeyPEM
}

// DeviceID returns the current device ID (bootstrap or mTLS depending on phase).
func (m *Manager) DeviceID() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.phase == PhaseMTLS && m.mtlsDeviceID != "" {
		return m.mtlsDeviceID
	}
	return m.deviceID
}

// Start begins the transport lifecycle. In bootstrap mode, it opens the bootstrap
// port and waits for peers. In mTLS mode, it opens the production port directly.
func (m *Manager) Start(ctx context.Context) error {
	ctx, m.cancel = context.WithCancel(ctx)

	switch m.Phase() {
	case PhaseBootstrap:
		return m.startBootstrap(ctx)
	case PhaseMTLS:
		return m.startMTLS(ctx)
	default:
		return fmt.Errorf("transport: unexpected phase %s", m.phase)
	}
}

// StartBootstrapOnly opens just the bootstrap listener for device pairing,
// without touching the mTLS port (which is managed by the gRPC server).
func (m *Manager) StartBootstrapOnly(ctx context.Context) error {
	return m.startBootstrap(ctx)
}

// Stop gracefully shuts down all listeners.
func (m *Manager) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.closeBootstrap()
	m.closeMTLS()
	close(m.done)
}

// BootstrapListener returns the bootstrap listener (nil if not in bootstrap phase).
func (m *Manager) BootstrapListener() net.Listener {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.bootstrapListener
}

// MTLSListener returns the mTLS listener (nil if not yet started).
func (m *Manager) MTLSListener() net.Listener {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.mtlsListener
}

// TransitionToMTLS transitions from bootstrap to mTLS phase.
// This closes the bootstrap port and opens the mTLS port.
// Called after successful certificate exchange.
func (m *Manager) TransitionToMTLS(ctx context.Context, deviceCertPEM, deviceKeyPEM []byte) error {
	m.mu.Lock()
	if m.phase != PhaseBootstrap && m.phase != PhaseRenewing {
		m.mu.Unlock()
		return fmt.Errorf("transport: cannot transition from phase %s", m.phase)
	}
	m.mu.Unlock()

	// Update device credentials.
	m.cfg.DeviceCertPEM = deviceCertPEM
	m.cfg.DeviceKeyPEM = deviceKeyPEM

	newID, err := ca.DeviceID(deviceCertPEM)
	if err != nil {
		return fmt.Errorf("transport: compute new device ID: %w", err)
	}

	// Close bootstrap port.
	m.closeBootstrap()
	m.logger.Info("transport: bootstrap port closed", "addr", m.cfg.BootstrapAddr)

	// Update state.
	m.mu.Lock()
	m.mtlsDeviceID = newID
	m.phase = PhaseMTLS
	m.mu.Unlock()

	m.logger.Info("transport: transitioned to mTLS",
		"device_id", newID,
		"addr", m.cfg.MTLSAddr)

	// Start mTLS listener.
	return m.startMTLS(ctx)
}

// EnableRenewal temporarily transitions to renewing phase, re-opening the
// bootstrap port for certificate exchange. After renewal completes or times
// out, the bootstrap port is closed again.
func (m *Manager) EnableRenewal(ctx context.Context) error {
	m.mu.Lock()
	if m.phase != PhaseMTLS {
		m.mu.Unlock()
		return fmt.Errorf("transport: can only renew from mTLS phase, current: %s", m.phase)
	}
	m.phase = PhaseRenewing
	m.mu.Unlock()

	m.logger.Info("transport: entering renewal mode, opening bootstrap port",
		"addr", m.cfg.BootstrapAddr,
		"timeout", m.cfg.BootstrapTimeout)

	if err := m.startBootstrap(ctx); err != nil {
		m.mu.Lock()
		m.phase = PhaseMTLS
		m.mu.Unlock()
		return fmt.Errorf("transport: start renewal bootstrap: %w", err)
	}

	// Auto-close bootstrap after timeout (0 = keep open until context cancelled).
	if m.cfg.BootstrapTimeout > 0 {
		go func() {
			timer := time.NewTimer(m.cfg.BootstrapTimeout)
			defer timer.Stop()
			select {
			case <-timer.C:
				m.logger.Warn("transport: renewal timeout, closing bootstrap port")
				m.closeBootstrap()
				m.mu.Lock()
				m.phase = PhaseMTLS
				m.mu.Unlock()
			case <-ctx.Done():
			}
		}()
	}

	return nil
}

// AddTrustedPeer records a peer that completed bootstrap.
func (m *Manager) AddTrustedPeer(deviceID string, certPEM []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.trustedPeers[deviceID] = certPEM
}

// TrustedPeers returns a copy of the trusted peers map.
func (m *Manager) TrustedPeers() map[string][]byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	peers := make(map[string][]byte, len(m.trustedPeers))
	for k, v := range m.trustedPeers {
		peers[k] = v
	}
	return peers
}

// hasMTLSCerts checks if we have valid CA-signed device certificates.
func (m *Manager) hasMTLSCerts() bool {
	if len(m.cfg.DeviceCertPEM) == 0 || len(m.cfg.DeviceKeyPEM) == 0 {
		return false
	}
	// Verify the cert can form a valid TLS keypair.
	_, err := tls.X509KeyPair(m.cfg.DeviceCertPEM, m.cfg.DeviceKeyPEM)
	if err != nil {
		return false
	}
	// Verify the cert is signed by our CA.
	if m.cfg.CA != nil {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(m.cfg.CA.RootCertPEM())
		certBlock, _ := decodeCertFromPEM(m.cfg.DeviceCertPEM)
		if certBlock != nil {
			_, err := certBlock.Verify(x509.VerifyOptions{Roots: pool})
			if err != nil {
				return false
			}
		}
	}
	return true
}

// startBootstrap opens the bootstrap listener with self-signed TLS.
func (m *Manager) startBootstrap(ctx context.Context) error {
	cert, err := tls.X509KeyPair(m.cfg.BootstrapCertPEM, m.cfg.BootstrapKeyPEM)
	if err != nil {
		return fmt.Errorf("transport: load bootstrap keypair: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// Bootstrap uses self-signed certs, so we verify manually via device ID.
		ClientAuth: tls.RequestClientCert,
		MinVersion: tls.VersionTLS13,
	}

	lis, err := tls.Listen("tcp", m.cfg.BootstrapAddr, tlsCfg)
	if err != nil {
		return fmt.Errorf("transport: bootstrap listen %s: %w", m.cfg.BootstrapAddr, err)
	}

	m.mu.Lock()
	m.bootstrapListener = lis
	m.mu.Unlock()

	m.logger.Info("transport: bootstrap listener started",
		"addr", lis.Addr().String(),
		"device_id", m.deviceID)

	// Auto-close bootstrap after timeout (only in bootstrap phase, not renewal).
	// Timeout of 0 means keep open until context cancelled.
	if m.Phase() == PhaseBootstrap && m.cfg.BootstrapTimeout > 0 {
		go func() {
			timer := time.NewTimer(m.cfg.BootstrapTimeout)
			defer timer.Stop()
			select {
			case <-timer.C:
				m.logger.Warn("transport: bootstrap timeout, no peers connected")
				m.closeBootstrap()
			case <-ctx.Done():
			}
		}()
	}

	return nil
}

// startMTLS opens the production mTLS listener.
func (m *Manager) startMTLS(ctx context.Context) error {
	cert, err := tls.X509KeyPair(m.cfg.DeviceCertPEM, m.cfg.DeviceKeyPEM)
	if err != nil {
		return fmt.Errorf("transport: load mtls keypair: %w", err)
	}

	caPool := x509.NewCertPool()
	if m.cfg.CA != nil {
		caPool.AppendCertsFromPEM(m.cfg.CA.RootCertPEM())
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS13,
	}

	lis, err := tls.Listen("tcp", m.cfg.MTLSAddr, tlsCfg)
	if err != nil {
		return fmt.Errorf("transport: mtls listen %s: %w", m.cfg.MTLSAddr, err)
	}

	m.mu.Lock()
	m.mtlsListener = lis
	m.mu.Unlock()

	m.logger.Info("transport: mTLS listener started",
		"addr", lis.Addr().String(),
		"device_id", m.mtlsDeviceID)

	return nil
}

// closeBootstrap shuts down the bootstrap listener.
func (m *Manager) closeBootstrap() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.bootstrapListener != nil {
		_ = m.bootstrapListener.Close()
		m.bootstrapListener = nil
	}
}

// closeMTLS shuts down the mTLS listener.
func (m *Manager) closeMTLS() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mtlsListener != nil {
		_ = m.mtlsListener.Close()
		m.mtlsListener = nil
	}
}
