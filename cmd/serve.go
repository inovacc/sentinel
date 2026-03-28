package cmd

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/inovacc/sentinel/internal/ca"
	"github.com/inovacc/sentinel/internal/datadir"
	"github.com/inovacc/sentinel/internal/exec"
	"github.com/inovacc/sentinel/internal/fleet"
	"github.com/inovacc/sentinel/internal/fs"
	sentinelgrpc "github.com/inovacc/sentinel/internal/grpc"
	"github.com/inovacc/sentinel/internal/logrotate"
	"github.com/inovacc/sentinel/internal/rbac"
	"github.com/inovacc/sentinel/internal/sandbox"
	"github.com/inovacc/sentinel/internal/serverinfo"
	"github.com/inovacc/sentinel/internal/session"
	"github.com/inovacc/sentinel/internal/settings"
	"github.com/inovacc/sentinel/pkg/transport"
	"github.com/spf13/cobra"

	_ "modernc.org/sqlite"
)

func newServeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the sentinel daemon (foreground)",
		Long:  `Starts the sentinel gRPC daemon in the foreground with mTLS authentication and bootstrap port for new device pairing.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDaemon()
		},
	}
	return cmd
}

func runDaemon() error {
	// Load configuration.
	cfg, err := settings.Load(datadir.ConfigPath())
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Set up logging.
	logPath := cfg.Logging.File
	if logPath == "" {
		logPath = datadir.LogPath()
	}

	var logWriter *logrotate.Writer
	maxSize := cfg.Logging.MaxSizeMB
	if maxSize == 0 {
		maxSize = 50
	}
	maxFiles := cfg.Logging.MaxFiles
	if maxFiles == 0 {
		maxFiles = 5
	}
	logWriter, err = logrotate.New(logPath, maxSize, maxFiles)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "warning: failed to open log file %s: %v\n", logPath, err)
	}

	var logger *slog.Logger
	if logWriter != nil {
		defer func() { _ = logWriter.Close() }()
		logger = slog.New(slog.NewJSONHandler(logWriter, &slog.HandlerOptions{
			Level: parseLogLevel(cfg.Logging.Level),
		}))
	} else {
		logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
			Level: parseLogLevel(cfg.Logging.Level),
		}))
	}

	logger.Info("sentinel daemon starting", "version", version)

	// Ensure data directory exists.
	if err := os.MkdirAll(datadir.Root(), 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	// Write PID file.
	if err := serverinfo.WritePID(datadir.Root()); err != nil {
		return fmt.Errorf("write PID: %w", err)
	}
	defer func() { _ = serverinfo.RemovePID(datadir.Root()) }()

	// Load CA and certificates.
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

	certPEM, err := os.ReadFile(filepath.Join(certDir, "device.crt"))
	if err != nil {
		return fmt.Errorf("read device cert: %w", err)
	}

	keyPEM, err := os.ReadFile(filepath.Join(certDir, "device.key"))
	if err != nil {
		return fmt.Errorf("read device key: %w", err)
	}

	deviceID, _ := ca.DeviceID(certPEM)
	logger.Info("device identity loaded", "device_id", deviceID)

	grpcAddr := cfg.Listen.GRPC
	if grpcAddr == "" {
		grpcAddr = ":7400"
	}

	bootstrapAddr := ":7399"

	// Initialize SQLite database.
	db, err := sql.Open("sqlite", datadir.DBPath())
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() { _ = db.Close() }()

	// Initialize fleet registry.
	registry, err := fleet.NewRegistry(db)
	if err != nil {
		return fmt.Errorf("init fleet registry: %w", err)
	}

	// Initialize sandbox.
	sandboxRoot := cfg.Sandbox.Root
	if sandboxRoot == "" {
		sandboxRoot, _ = datadir.SandboxRoot()
	}

	sb, err := sandbox.New(sandbox.Config{
		Root:            sandboxRoot,
		ReadPatterns:    cfg.Sandbox.Allowlist.Read,
		ExecAllowlist:   cfg.Sandbox.Allowlist.Exec,
		BlockedCommands: cfg.Sandbox.Allowlist.BlockedCommands,
	})
	if err != nil {
		return fmt.Errorf("init sandbox: %w", err)
	}
	logger.Info("sandbox initialized", "root", sb.Root())

	// Initialize session manager.
	sessionMgr, err := session.NewManager(db)
	if err != nil {
		return fmt.Errorf("init session manager: %w", err)
	}

	// Recover interrupted sessions.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	recovered, err := sessionMgr.RecoverInterrupted(ctx)
	if err != nil {
		logger.Warn("session recovery failed", "error", err)
	} else if recovered > 0 {
		logger.Info("recovered interrupted sessions", "count", recovered)
	}

	// --- Transport: Bootstrap + mTLS ---

	// Generate or load bootstrap identity.
	certStore, err := transport.NewCertStore(certDir)
	if err != nil {
		return fmt.Errorf("cert store: %w", err)
	}

	var bootCert, bootKey []byte
	if certStore.HasBootstrap() {
		bootCert, bootKey, err = certStore.LoadBootstrap()
		if err != nil {
			return fmt.Errorf("load bootstrap identity: %w", err)
		}
	} else {
		bootCert, bootKey, err = transport.GenerateBootstrapIdentity()
		if err != nil {
			return fmt.Errorf("generate bootstrap identity: %w", err)
		}
		if err := certStore.SaveBootstrap(bootCert, bootKey); err != nil {
			return fmt.Errorf("save bootstrap identity: %w", err)
		}
	}

	transportMgr, err := transport.NewManager(transport.Config{
		BootstrapAddr:    bootstrapAddr,
		MTLSAddr:         grpcAddr,
		CA:               authority,
		DeviceCertPEM:    certPEM,
		DeviceKeyPEM:     keyPEM,
		BootstrapCertPEM: bootCert,
		BootstrapKeyPEM:  bootKey,
		BootstrapTimeout: 0, // No timeout — keep bootstrap open for pairing.
		Logger:           logger,
		OnPeerAccepted: func(peerID string, peerCert []byte, role string) (bool, error) {
			logger.Info("pairing request received",
				"peer_device_id", peerID,
				"requested_role", role)

			// Auto-accept if configured, otherwise add as pending.
			if cfg.Security.AutoAccept {
				logger.Info("auto-accepting peer", "device_id", peerID)
				return true, nil
			}

			// Add to pending list for manual approval.
			if err := registry.AddPending(&fleet.Device{
				DeviceID: peerID,
				CertPEM:  peerCert,
				Role:     role,
			}); err != nil {
				logger.Error("failed to add pending device", "error", err)
				return false, err
			}

			logger.Info("device added to pending list — use 'sentinel pair accept' to approve",
				"device_id", peerID)

			// For now, auto-accept to complete the handshake.
			// In production, this would wait for manual approval.
			return true, nil
		},
	})
	if err != nil {
		return fmt.Errorf("init transport: %w", err)
	}

	// Start bootstrap listener for device pairing (regardless of mTLS state).
	// The gRPC server handles mTLS on :7400 separately.
	if err := transportMgr.StartBootstrapOnly(ctx); err != nil {
		logger.Warn("could not start bootstrap port", "error", err)
	} else {
		defer transportMgr.Stop()
		bs := transport.NewBootstrapServer(transportMgr, version)
		go func() {
			_ = bs.Serve(ctx)
		}()
		logger.Info("bootstrap server started for pairing", "addr", bootstrapAddr)
	}

	// Print startup info.
	phase := "mtls"
	if transportMgr.BootstrapListener() != nil {
		phase = "mtls+bootstrap"
	}
	printStartupBanner(deviceID, grpcAddr, bootstrapAddr, phase)

	// Create services.
	runner := exec.NewRunner(sb)
	fsSvc := fs.NewService(sb)

	// Create gRPC server with mTLS.
	policy := rbac.NewPolicy()
	grpcServer, err := sentinelgrpc.NewServer(certPEM, keyPEM, authority.RootCertPEM(), policy)
	if err != nil {
		return fmt.Errorf("init gRPC server: %w", err)
	}

	// Register services.
	grpcServer.RegisterExecService(sentinelgrpc.NewExecService(runner, sessionMgr))
	grpcServer.RegisterFileSystemService(sentinelgrpc.NewFileSystemService(fsSvc))
	grpcServer.RegisterSessionService(sentinelgrpc.NewSessionService(sessionMgr))

	logger.Info("starting gRPC server", "addr", grpcAddr)

	// Start gRPC server on the mTLS port.
	errCh := make(chan error, 1)
	go func() {
		errCh <- grpcServer.Serve(grpcAddr)
	}()

	// Wait for shutdown signal or server error.
	select {
	case <-ctx.Done():
		logger.Info("shutting down...")
		grpcServer.Stop()
		return nil
	case err := <-errCh:
		return fmt.Errorf("gRPC server: %w", err)
	}
}

func printStartupBanner(deviceID, grpcAddr, bootstrapAddr, phase string) {
	hostname, _ := os.Hostname()
	localIPs := getLocalIPs()
	publicIP := getPublicIP()

	info := struct {
		Name          string   `json:"name"`
		Version       string   `json:"version"`
		Hostname      string   `json:"hostname"`
		OS            string   `json:"os"`
		Arch          string   `json:"arch"`
		GRPCAddr      string   `json:"grpc_addr"`
		BootstrapAddr string   `json:"bootstrap_addr"`
		Phase         string   `json:"phase"`
		DeviceID      string   `json:"device_id"`
		LocalIPs      []string `json:"local_ips"`
		PublicIP       string   `json:"public_ip"`
		StartedAt     string   `json:"started_at"`
	}{
		Name:          "sentinel",
		Version:       version,
		Hostname:      hostname,
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		GRPCAddr:      grpcAddr,
		BootstrapAddr: bootstrapAddr,
		Phase:         phase,
		DeviceID:      deviceID,
		LocalIPs:      localIPs,
		PublicIP:      publicIP,
		StartedAt:     time.Now().Format(time.RFC3339),
	}

	enc := json.NewEncoder(os.Stderr)
	enc.SetIndent("", "  ")
	_ = enc.Encode(info)
}

func getLocalIPs() []string {
	var ips []string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ips
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
			ips = append(ips, ipNet.IP.String())
		}
	}
	return ips
}

func getPublicIP() string {
	client := &http.Client{Timeout: 3 * time.Second}
	endpoints := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
	}
	for _, url := range endpoints {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			continue
		}
		ip := strings.TrimSpace(string(body))
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	return "(unavailable)"
}

func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
