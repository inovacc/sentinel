package cmd

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/inovacc/sentinel/internal/audit"
	"github.com/inovacc/sentinel/internal/ca"
	"github.com/inovacc/sentinel/internal/datadir"
	"github.com/inovacc/sentinel/internal/fleet"
	"github.com/inovacc/sentinel/internal/settings"
	"github.com/inovacc/sentinel/pkg/transport"
	"github.com/spf13/cobra"
)

func newBootstrapCmd() *cobra.Command {
	bootstrapCmd := &cobra.Command{
		Use:   "bootstrap",
		Short: "Bootstrap handshake operations",
	}

	bootstrapCmd.AddCommand(
		newBootstrapTestCmd(),
		newBootstrapConnectCmd(),
	)

	return bootstrapCmd
}

func newBootstrapTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test",
		Short: "Run a full bootstrap handshake test (server + client on localhost)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBootstrapTest()
		},
	}
}

func newBootstrapConnectCmd() *cobra.Command {
	connectCmd := &cobra.Command{
		Use:   "connect [address]",
		Short: "Connect to a remote sentinel via bootstrap handshake",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			role, _ := cmd.Flags().GetString("role")
			force, _ := cmd.Flags().GetBool("force")
			return runBootstrapConnect(args[0], role, force)
		},
	}
	connectCmd.Flags().StringP("role", "r", "operator", "Role to request: admin, operator, reader")
	connectCmd.Flags().Bool("force", false, "Accept a peer whose CA changed since you last paired (use only if you trust the change)")
	return connectCmd
}

func runBootstrapTest() error {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Load CA for the server side.
	caDir, err := datadir.CADir()
	if err != nil {
		return fmt.Errorf("ca dir: %w", err)
	}

	authority, err := ca.Load(caDir)
	if err != nil {
		return fmt.Errorf("load CA (run 'sentinel ca init' first): %w", err)
	}

	// Generate bootstrap identities for server and client.
	serverCert, serverKey, err := transport.GenerateBootstrapIdentity()
	if err != nil {
		return fmt.Errorf("generate server bootstrap identity: %w", err)
	}

	clientCert, clientKey, err := transport.GenerateBootstrapIdentity()
	if err != nil {
		return fmt.Errorf("generate client bootstrap identity: %w", err)
	}

	serverDeviceID, _ := ca.DeviceID(serverCert)
	clientDeviceID, _ := ca.DeviceID(clientCert)

	_, _ = fmt.Fprintf(os.Stderr, "\n=== Bootstrap Handshake Test ===\n\n")
	_, _ = fmt.Fprintf(os.Stderr, "Server Device ID: %s\n", serverDeviceID)
	_, _ = fmt.Fprintf(os.Stderr, "Client Device ID: %s\n\n", clientDeviceID)

	// --- Start Server ---
	serverManager, err := transport.NewManager(transport.Config{
		BootstrapAddr:    "127.0.0.1:0",
		MTLSAddr:         "127.0.0.1:0",
		CA:               authority,
		BootstrapCertPEM: serverCert,
		BootstrapKeyPEM:  serverKey,
		BootstrapTimeout: 30 * time.Second,
		Logger:           logger,
		OnPeerAccepted: func(peerID string, peerCert []byte, role string) (bool, error) {
			_, _ = fmt.Fprintf(os.Stderr, "[server] Peer requesting access: %s (role: %s)\n", peerID, role)
			_, _ = fmt.Fprintf(os.Stderr, "[server] ACCEPTED\n")
			return true, nil
		},
	})
	if err != nil {
		return fmt.Errorf("create server manager: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := serverManager.Start(ctx); err != nil {
		return fmt.Errorf("start server: %w", err)
	}
	defer serverManager.Stop()

	serverAddr := serverManager.BootstrapListener().Addr().String()
	_, _ = fmt.Fprintf(os.Stderr, "[server] Bootstrap listening on %s\n\n", serverAddr)

	// Start bootstrap server handler.
	bs := transport.NewBootstrapServer(serverManager, version)
	go func() {
		_ = bs.Serve(ctx)
	}()

	// Give server time to start accepting.
	time.Sleep(100 * time.Millisecond)

	// --- Start Client ---
	_, _ = fmt.Fprintf(os.Stderr, "[client] Connecting to %s...\n", serverAddr)

	clientManager, err := transport.NewManager(transport.Config{
		BootstrapAddr:    "127.0.0.1:0",
		MTLSAddr:         "127.0.0.1:0",
		BootstrapCertPEM: clientCert,
		BootstrapKeyPEM:  clientKey,
		BootstrapTimeout: 30 * time.Second,
		Logger:           logger,
	})
	if err != nil {
		return fmt.Errorf("create client manager: %w", err)
	}

	bc := transport.NewBootstrapClient(clientManager, version)
	result, err := bc.Connect(ctx, serverAddr, ca.RoleOperator)
	if err != nil {
		return fmt.Errorf("bootstrap connect: %w", err)
	}

	// --- Print Results ---
	_, _ = fmt.Fprintf(os.Stderr, "\n=== Bootstrap Handshake Complete ===\n\n")

	// Compute the new device ID from the signed cert.
	newDeviceID := "(none)"
	if len(result.SignedCertPEM) > 0 {
		newDeviceID, _ = ca.DeviceID(result.SignedCertPEM)
	}

	output := struct {
		Status        string `json:"status"`
		PeerDeviceID  string `json:"peer_device_id"`
		OldDeviceID   string `json:"old_device_id"`
		NewDeviceID   string `json:"new_device_id"`
		AssignedRole  string `json:"assigned_role"`
		MTLSAddr      string `json:"mtls_addr"`
		HasSignedCert bool   `json:"has_signed_cert"`
		HasCACert     bool   `json:"has_ca_cert"`
	}{
		Status:        "success",
		PeerDeviceID:  result.PeerDeviceID,
		OldDeviceID:   clientDeviceID,
		NewDeviceID:   newDeviceID,
		AssignedRole:  result.AssignedRole,
		MTLSAddr:      result.MTLSAddr,
		HasSignedCert: len(result.SignedCertPEM) > 0,
		HasCACert:     len(result.CACertPEM) > 0,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

func runBootstrapConnect(addr, role string, force bool) error {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Generate or load bootstrap identity.
	certDir, err := datadir.CertDir()
	if err != nil {
		return fmt.Errorf("cert dir: %w", err)
	}

	store, err := transport.NewCertStore(certDir)
	if err != nil {
		return fmt.Errorf("cert store: %w", err)
	}

	var bootCert, bootKey []byte
	if store.HasBootstrap() {
		bootCert, bootKey, err = store.LoadBootstrap()
		if err != nil {
			return fmt.Errorf("load bootstrap identity: %w", err)
		}
		_, _ = fmt.Fprintf(os.Stderr, "Loaded existing bootstrap identity\n")
	} else {
		bootCert, bootKey, err = transport.GenerateBootstrapIdentity()
		if err != nil {
			return fmt.Errorf("generate bootstrap identity: %w", err)
		}
		if err := store.SaveBootstrap(bootCert, bootKey); err != nil {
			return fmt.Errorf("save bootstrap identity: %w", err)
		}
		_, _ = fmt.Fprintf(os.Stderr, "Generated new bootstrap identity\n")
	}

	deviceID, _ := ca.DeviceID(bootCert)
	_, _ = fmt.Fprintf(os.Stderr, "Device ID: %s\n", deviceID)
	_, _ = fmt.Fprintf(os.Stderr, "Connecting to %s...\n", addr)

	clientManager, err := transport.NewManager(transport.Config{
		BootstrapAddr:    "127.0.0.1:0",
		MTLSAddr:         "127.0.0.1:0",
		BootstrapCertPEM: bootCert,
		BootstrapKeyPEM:  bootKey,
		BootstrapTimeout: 30 * time.Second,
		Logger:           logger,
	})
	if err != nil {
		return fmt.Errorf("create client manager: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	bc := transport.NewBootstrapClient(clientManager, version)
	result, err := bc.Connect(ctx, addr, role)
	if err != nil {
		return fmt.Errorf("bootstrap connect: %w", err)
	}

	// Pin the CA we paired with so a later rotation by the peer is detectable
	// instead of a silent handshake break. A non-empty but unparseable CA is a
	// hard error rather than a silent unpinned fallback.
	caFingerprint, err := caPinFingerprint(result.CACertPEM)
	if err != nil {
		return fmt.Errorf("peer CA certificate is unparseable, refusing to pair: %w", err)
	}

	// Guard against silently re-pairing a known peer whose CA changed
	// (rotation / MITM) BEFORE overwriting local mTLS material. Fails closed: if
	// the trust store is unavailable we refuse unless --force is given.
	reg, cleanup, regErr := openRegistry()
	if regErr != nil {
		if !force {
			return fmt.Errorf("cannot open the local trust store (%v); re-run with --force to pair anyway", regErr)
		}
		_, _ = fmt.Fprintf(os.Stderr, "warning: trust store unavailable (%v); --force given, proceeding without the CA-change check\n", regErr)
	} else {
		defer cleanup()
		existing, getErr := reg.Get(result.PeerDeviceID)
		if msg, refuse := repairGuard(existing, getErr, caFingerprint, force); refuse {
			// Record the refusal as a critical pairing.conflict before aborting.
			// This is the connect-side mirror of the server's pairing audit: a
			// known peer whose CA changed (rotation / MITM) was refused.
			auditLog, aerr := connectAuditLogger()
			if aerr != nil {
				return fmt.Errorf("%s (additionally: could not open audit log to record the conflict: %v)", msg, aerr)
			}
			defer func() { _ = auditLog.Close() }()
			return recordPairingConflict(auditLog, result.PeerDeviceID, msg)
		}
	}

	// Save the received mTLS certs.
	if len(result.SignedCertPEM) > 0 && len(result.CACertPEM) > 0 {
		if err := store.SaveMTLS(result.SignedCertPEM, clientManager.DeviceKeyPEM(), result.CACertPEM); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "warning: failed to save mTLS certs: %v\n", err)
		} else {
			_, _ = fmt.Fprintf(os.Stderr, "Saved mTLS certificates to %s\n", filepath.Join(certDir))
		}
	}

	// Register/refresh the server in the local fleet registry, pinning its CA.
	if reg != nil {
		mtlsAddr := buildMTLSAddr(addr, result.MTLSAddr)
		peerDevice := &fleet.Device{
			DeviceID:      result.PeerDeviceID,
			Address:       mtlsAddr,
			Role:          "admin", // The server that signed our cert is the authority.
			Status:        fleet.StatusOnline,
			CAFingerprint: caFingerprint,
			CACertPEM:     result.CACertPEM,
		}
		if err := reg.AddPending(peerDevice); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "warning: failed to register peer: %v\n", err)
		} else if err := reg.Accept(result.PeerDeviceID, "admin"); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "warning: failed to accept peer: %v\n", err)
		} else {
			_, _ = fmt.Fprintf(os.Stderr, "Registered peer %s in fleet registry\n", result.PeerDeviceID)
		}
	}

	// Print result.
	newDeviceID := "(none)"
	if len(result.SignedCertPEM) > 0 {
		newDeviceID, _ = ca.DeviceID(result.SignedCertPEM)
	}

	output := struct {
		Status       string `json:"status"`
		PeerDeviceID string `json:"peer_device_id"`
		NewDeviceID  string `json:"new_device_id"`
		AssignedRole string `json:"assigned_role"`
		MTLSAddr     string `json:"mtls_addr"`
	}{
		Status:       "success",
		PeerDeviceID: result.PeerDeviceID,
		NewDeviceID:  newDeviceID,
		AssignedRole: result.AssignedRole,
		MTLSAddr:     result.MTLSAddr,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

// recordPairingConflict emits the critical pairing.conflict event for a refused
// re-pair and returns the refusal error to the caller. It is critical and
// fail-closed: if the conflict itself cannot be audited, the returned error says
// so rather than letting the refusal go unrecorded. On success it returns the
// original refusal message as the error (the conflict is still a refusal).
func recordPairingConflict(auditLog audit.Logger, deviceID, msg string) error {
	if rerr := auditLog.Record(context.Background(), audit.Event{
		Type:    audit.EventPairingConflict,
		Outcome: audit.OutcomeDeny,
		Target:  deviceID,
		Detail:  map[string]any{"device_id": deviceID, "reason": "ca-changed"},
	}); rerr != nil {
		return fmt.Errorf("%s (additionally: refusing to proceed with an unaudited conflict: %v)", msg, rerr)
	}
	return fmt.Errorf("%s", msg)
}

// connectAuditLogger builds the security audit logger from settings for the
// client-side connect flow, so a pairing.conflict refusal is recorded with the
// same store and posture the daemon uses. The caller owns Close.
func connectAuditLogger() (audit.Logger, error) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := settings.Load(datadir.ConfigPath())
	if err != nil {
		cfg = settings.DefaultConfig()
	}
	return buildAuditLogger(cfg, logger)
}

// caPinFingerprint returns the fingerprint to pin for a peer's CA. An empty CA
// yields no pin, but a non-empty yet unparseable CA is a hard error: silently
// pinning "" would make a malformed CA indistinguishable from an unpinned peer
// and defeat rotation detection.
func caPinFingerprint(caCertPEM []byte) (string, error) {
	if len(caCertPEM) == 0 {
		return "", nil
	}
	return ca.Fingerprint(caCertPEM)
}

// repairGuard decides whether to refuse a (re-)pairing. It fails closed: a
// trust-store lookup error other than "not found" refuses unless --force, as
// does a known peer whose pinned CA changed.
func repairGuard(existing *fleet.Device, lookupErr error, newFingerprint string, force bool) (string, bool) {
	if lookupErr != nil && !errors.Is(lookupErr, sql.ErrNoRows) {
		if force {
			return "", false
		}
		return fmt.Sprintf("cannot verify the peer against the local trust store: %v; re-run with --force to pair anyway", lookupErr), true
	}
	if conflict, msg := pairingConflict(existing, newFingerprint); conflict && !force {
		return msg, true
	}
	return "", false
}

// buildMTLSAddr takes the bootstrap address (e.g., "192.168.1.100:7399")
// and the mTLS addr from the server (e.g., ":7400") and builds a full
// mTLS address (e.g., "192.168.1.100:7400").
func buildMTLSAddr(bootstrapAddr, mtlsAddr string) string {
	host, _, err := net.SplitHostPort(bootstrapAddr)
	if err != nil {
		return bootstrapAddr
	}
	_, port, err := net.SplitHostPort(mtlsAddr)
	if err != nil {
		port = "7400"
	}
	return net.JoinHostPort(host, port)
}
