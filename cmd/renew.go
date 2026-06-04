package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/inovacc/sentinel/internal/audit"
	"github.com/inovacc/sentinel/internal/ca"
	"github.com/inovacc/sentinel/internal/datadir"
	"github.com/inovacc/sentinel/internal/settings"
	"github.com/inovacc/sentinel/pkg/transport"
	"github.com/spf13/cobra"
)

// portOnly returns just the port of a host:port listen address (e.g. ":7399"
// or "0.0.0.0:7399" -> "7399"), falling back to "7399" when unparseable.
func portOnly(addr string) string {
	if _, port, err := net.SplitHostPort(addr); err == nil && port != "" {
		return port
	}
	return "7399"
}

// buildRenewOnPeerAccepted returns an OnPeerAccepted callback for the renew
// path that emits a critical cert.renew event for each re-paired peer,
// failing closed if the audit write fails.
func buildRenewOnPeerAccepted(logger *slog.Logger, auditLog audit.Logger) func(string, []byte, string) (bool, error) {
	return func(peerID string, peerCert []byte, role string) (bool, error) {
		logger.Info("renew: re-pairing peer", "peer_device_id", peerID, "role", role)
		if aerr := auditLog.Record(context.Background(), audit.Event{
			Type:    audit.EventCertRenew,
			Outcome: audit.OutcomeAllow,
			Target:  peerID,
			Detail:  map[string]any{"device_id": peerID, "role": role},
		}); aerr != nil {
			return false, fmt.Errorf("renew: refusing to complete unaudited cert renewal: %w", aerr)
		}
		return true, nil
	}
}

func newRenewCmd() *cobra.Command {
	var window time.Duration
	cmd := &cobra.Command{
		Use:   "renew",
		Short: "Briefly re-open the bootstrap port so peers can re-pair after a CA change",
		Long: `Opens a time-boxed pairing window on the bootstrap port using this host's
existing identity and CA, then closes it. Run this on the host whose CA was
rotated; on each client run:

  sentinel connect <this-host:7399> --force

The mTLS data port is unaffected. This works because a steady-state mTLS daemon
now keeps the bootstrap port closed, leaving it free for this temporary window.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRenew(window)
		},
	}
	cmd.Flags().DurationVar(&window, "window", 5*time.Minute, "How long to keep the pairing window open")
	return cmd
}

func runRenew(window time.Duration) error {
	if window <= 0 {
		return fmt.Errorf("renew: --window must be positive")
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	caDir, err := datadir.CADir()
	if err != nil {
		return fmt.Errorf("ca dir: %w", err)
	}
	authority, err := ca.Load(caDir)
	if err != nil {
		return fmt.Errorf("load CA (run 'sentinel ca init' first): %w", err)
	}

	certDir, err := datadir.CertDir()
	if err != nil {
		return fmt.Errorf("cert dir: %w", err)
	}
	store, err := transport.NewCertStore(certDir)
	if err != nil {
		return fmt.Errorf("cert store: %w", err)
	}
	if !store.HasMTLS() {
		return fmt.Errorf("no mTLS identity yet — use 'sentinel connect' for initial pairing, not renew")
	}
	certPEM, keyPEM, _, err := store.LoadMTLS()
	if err != nil {
		return fmt.Errorf("load mTLS identity: %w", err)
	}
	bootCert, bootKey, err := loadOrCreateBootstrapIdentity(store)
	if err != nil {
		return err
	}

	cfg, err := settings.Load(datadir.ConfigPath())
	if err != nil {
		cfg = settings.DefaultConfig()
	}
	bootstrapAddr := orDefault(cfg.Listen.Bootstrap, ":7399")

	auditLog, aerr := buildAuditLogger(cfg, logger)
	if aerr != nil {
		return aerr
	}
	defer func() { _ = auditLog.Close() }()
	_ = auditLog.Record(context.Background(), audit.Event{
		Type: audit.EventDaemonRenew, Outcome: audit.OutcomeAllow, Target: "self"})

	_, cleanup, err := openRegistry()
	if err != nil {
		return fmt.Errorf("open registry: %w", err)
	}
	defer cleanup()

	mgr, err := transport.NewManager(transport.Config{
		BootstrapAddr:    bootstrapAddr,
		MTLSAddr:         orDefault(cfg.Listen.GRPC, ":7400"),
		CA:               authority,
		DeviceCertPEM:    certPEM,
		DeviceKeyPEM:     keyPEM,
		BootstrapCertPEM: bootCert,
		BootstrapKeyPEM:  bootKey,
		BootstrapTimeout: window,
		Logger:           logger,
		OnPeerAccepted:   buildRenewOnPeerAccepted(logger, auditLog),
	})
	if err != nil {
		return fmt.Errorf("init transport: %w", err)
	}
	if mgr.Phase() != transport.PhaseMTLS {
		return fmt.Errorf("renew requires an established mTLS identity")
	}

	ctx, cancel := context.WithTimeout(context.Background(), window)
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	if err := mgr.EnableRenewal(ctx); err != nil {
		return fmt.Errorf("open renewal window: %w", err)
	}
	defer mgr.Stop()

	bs := transport.NewBootstrapServer(mgr, version)
	go func() {
		if err := bs.Serve(ctx); err != nil && ctx.Err() == nil {
			logger.Error("bootstrap server stopped", "error", err)
		}
	}()

	_, _ = fmt.Fprintf(os.Stderr,
		"Pairing window open on %s for %s.\n  On each client run: sentinel connect <this-host:%s> --force\n  (Ctrl-C to close early.)\n",
		bootstrapAddr, window, portOnly(bootstrapAddr))

	<-ctx.Done()
	_, _ = fmt.Fprintln(os.Stderr, "Pairing window closed.")
	return nil
}
