package cmd

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/inovacc/sentinel/internal/ca"
	"github.com/inovacc/sentinel/internal/datadir"
	"github.com/inovacc/sentinel/internal/exec"
	sentinelgrpc "github.com/inovacc/sentinel/internal/grpc"
	"github.com/inovacc/sentinel/internal/fs"
	"github.com/inovacc/sentinel/internal/logrotate"
	"github.com/inovacc/sentinel/internal/rbac"
	"github.com/inovacc/sentinel/internal/sandbox"
	"github.com/inovacc/sentinel/internal/serverinfo"
	"github.com/inovacc/sentinel/internal/session"
	"github.com/inovacc/sentinel/internal/settings"
	"github.com/spf13/cobra"

	_ "modernc.org/sqlite"
)

func newServeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Start the sentinel daemon (foreground)",
		Long:  `Starts the sentinel gRPC daemon in the foreground with mTLS authentication.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDaemon()
		},
	}
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
		// Fall back to stderr.
		fmt.Fprintf(os.Stderr, "warning: failed to open log file %s: %v\n", logPath, err)
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

	// Initialize SQLite database.
	db, err := sql.Open("sqlite", datadir.DBPath())
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() { _ = db.Close() }()

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
	grpcServer.RegisterExecService(sentinelgrpc.NewExecService(runner))
	grpcServer.RegisterFileSystemService(sentinelgrpc.NewFileSystemService(fsSvc))
	grpcServer.RegisterSessionService(sentinelgrpc.NewSessionService(sessionMgr))

	listenAddr := cfg.Listen.GRPC
	if listenAddr == "" {
		listenAddr = ":7400"
	}

	logger.Info("starting gRPC server", "addr", listenAddr)

	// Start server in goroutine.
	errCh := make(chan error, 1)
	go func() {
		errCh <- grpcServer.Serve(listenAddr)
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
