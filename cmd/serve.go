package cmd

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/inovacc/sentinel/internal/ca"
	"github.com/inovacc/sentinel/internal/datadir"
	"github.com/inovacc/sentinel/internal/discovery"
	"github.com/inovacc/sentinel/internal/exec"
	"github.com/inovacc/sentinel/internal/fleet"
	"github.com/inovacc/sentinel/internal/fs"
	sentinelgrpc "github.com/inovacc/sentinel/internal/grpc"
	"github.com/inovacc/sentinel/internal/logrotate"
	"github.com/inovacc/sentinel/internal/metrics"
	"github.com/inovacc/sentinel/internal/payload"
	"github.com/inovacc/sentinel/internal/rbac"
	"github.com/inovacc/sentinel/internal/sandbox"
	"github.com/inovacc/sentinel/internal/serverinfo"
	"github.com/inovacc/sentinel/internal/session"
	"github.com/inovacc/sentinel/internal/settings"
	"github.com/inovacc/sentinel/internal/worker"
	"github.com/inovacc/sentinel/pkg/transport"
	"github.com/spf13/cobra"

	_ "modernc.org/sqlite"
)

var serveJSON bool

func newServeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the sentinel daemon (foreground)",
		Long:  `Starts the sentinel gRPC daemon in the foreground with mTLS authentication and bootstrap port for new device pairing.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDaemon()
		},
	}
	cmd.Flags().BoolVar(&serveJSON, "json", false, "Output startup banner as JSON")
	return cmd
}

// runDaemon wires a cancellable signal context and runs the daemon until an
// interrupt/terminate signal or a fatal server error.
func runDaemon() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return runDaemonCtx(ctx)
}

// runDaemonCtx builds and serves the daemon under the given context. It is the
// testable seam: callers can supply their own cancellable context. buildDaemon
// always returns a (possibly partial) daemon so its acquired resources are torn
// down here even when construction fails.
func runDaemonCtx(ctx context.Context) error {
	d, err := buildDaemon(ctx)
	if d != nil {
		defer d.cleanup()
	}
	if err != nil {
		return err
	}
	return d.serve(ctx)
}

// daemon holds the wired components of a running sentinel daemon. It is
// assembled by buildDaemon and driven by serve.
type daemon struct {
	logger       *slog.Logger
	registry     *fleet.Registry
	sessionMgr   *session.Manager
	workerPool   *worker.Pool
	transportMgr *transport.Manager
	grpcServer   *sentinelgrpc.Server

	certDir       string
	deviceID      string
	grpcAddr      string
	bootstrapAddr string
	metricsAddr   string

	discoveryEnabled bool

	cleanups []func()
}

func (d *daemon) addCleanup(f func()) { d.cleanups = append(d.cleanups, f) }

// cleanup runs registered teardown functions in reverse (LIFO) order.
func (d *daemon) cleanup() {
	for i := len(d.cleanups) - 1; i >= 0; i-- {
		d.cleanups[i]()
	}
}

// buildDaemon loads configuration and assembles every component the daemon
// needs, without binding listening ports or starting the request loop. It
// always returns a non-nil *daemon carrying any resources acquired so far, so
// the caller can tear them down even on error.
func buildDaemon(ctx context.Context) (*daemon, error) {
	d := &daemon{}

	cfg, err := settings.Load(datadir.ConfigPath())
	if err != nil {
		return d, fmt.Errorf("load config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return d, fmt.Errorf("invalid config: %w", err)
	}

	logger, logClose := setupLogging(cfg)
	d.logger = logger
	d.addCleanup(func() { _ = logClose() })
	logger.Info("sentinel daemon starting", "version", version)

	if err := os.MkdirAll(datadir.Root(), 0o700); err != nil {
		return d, fmt.Errorf("create data dir: %w", err)
	}
	if err := serverinfo.WritePID(datadir.Root()); err != nil {
		return d, fmt.Errorf("write PID: %w", err)
	}
	d.addCleanup(func() { _ = serverinfo.RemovePID(datadir.Root()) })

	authority, certPEM, keyPEM, certDir, deviceID, err := loadDeviceIdentity()
	if err != nil {
		return d, err
	}
	d.certDir = certDir
	d.deviceID = deviceID
	logger.Info("device identity loaded", "device_id", deviceID)
	warnCertExpiry(logger, certPEM)

	d.grpcAddr = orDefault(cfg.Listen.GRPC, ":7400")
	d.bootstrapAddr = orDefault(cfg.Listen.Bootstrap, ":7399")
	d.metricsAddr = orDefault(cfg.Listen.Metrics, ":7401")
	d.discoveryEnabled = cfg.Discovery.Enabled

	db, err := sql.Open("sqlite", datadir.DBPath())
	if err != nil {
		return d, fmt.Errorf("open database: %w", err)
	}
	d.addCleanup(func() { _ = db.Close() })

	registry, sb, sessionMgr, err := openDataStores(db, cfg, logger)
	if err != nil {
		return d, err
	}
	d.registry = registry
	d.sessionMgr = sessionMgr

	if recovered, rerr := sessionMgr.RecoverInterrupted(ctx); rerr != nil {
		logger.Warn("session recovery failed", "error", rerr)
	} else if recovered > 0 {
		logger.Info("recovered interrupted sessions", "count", recovered)
	}

	d.workerPool, err = worker.NewPool(db, sb, worker.WithLogger(logger))
	if err != nil {
		return d, fmt.Errorf("init worker pool: %w", err)
	}
	d.addCleanup(func() { d.workerPool.Stop() })

	d.transportMgr, err = buildTransport(cfg, authority, certPEM, keyPEM, certDir, d.bootstrapAddr, d.grpcAddr, registry, logger)
	if err != nil {
		return d, err
	}

	rl := sentinelgrpc.NewRateLimiter(100, time.Second)
	policy := rbac.NewPolicy()
	d.grpcServer, err = sentinelgrpc.NewServer(certPEM, keyPEM, authority.RootCertPEM(), policy,
		sentinelgrpc.WithRateLimiter(rl),
	)
	if err != nil {
		return d, fmt.Errorf("init gRPC server: %w", err)
	}
	registerServices(d.grpcServer, sb, sessionMgr, d.workerPool, logger)

	return d, nil
}

// loadDeviceIdentity loads the fleet CA and the device's signed certificate and
// key from the data directory, and derives the device ID.
func loadDeviceIdentity() (authority *ca.CA, certPEM, keyPEM []byte, certDir, deviceID string, err error) {
	caDir, err := datadir.CADir()
	if err != nil {
		return nil, nil, nil, "", "", fmt.Errorf("ca dir: %w", err)
	}
	authority, err = ca.Load(caDir)
	if err != nil {
		return nil, nil, nil, "", "", fmt.Errorf("load CA (run 'sentinel ca init' first): %w", err)
	}
	certDir, err = datadir.CertDir()
	if err != nil {
		return nil, nil, nil, "", "", fmt.Errorf("cert dir: %w", err)
	}
	certPEM, err = os.ReadFile(filepath.Join(certDir, "device.crt"))
	if err != nil {
		return nil, nil, nil, "", "", fmt.Errorf("read device cert: %w", err)
	}
	keyPEM, err = os.ReadFile(filepath.Join(certDir, "device.key"))
	if err != nil {
		return nil, nil, nil, "", "", fmt.Errorf("read device key: %w", err)
	}
	deviceID, _ = ca.DeviceID(certPEM)
	return authority, certPEM, keyPEM, certDir, deviceID, nil
}

// openDataStores initializes the fleet registry, sandbox, and session manager
// over the shared database handle.
func openDataStores(db *sql.DB, cfg *settings.Config, logger *slog.Logger) (*fleet.Registry, *sandbox.Sandbox, *session.Manager, error) {
	registry, err := fleet.NewRegistry(db)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("init fleet registry: %w", err)
	}

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
		return nil, nil, nil, fmt.Errorf("init sandbox: %w", err)
	}
	logger.Info("sandbox initialized", "root", sb.Root())

	sessionMgr, err := session.NewManager(db)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("init session manager: %w", err)
	}
	return registry, sb, sessionMgr, nil
}

// buildTransport creates the bootstrap identity and the two-phase transport
// manager. Listeners are not bound until serve runs.
func buildTransport(cfg *settings.Config, authority *ca.CA, certPEM, keyPEM []byte, certDir, bootstrapAddr, grpcAddr string, registry *fleet.Registry, logger *slog.Logger) (*transport.Manager, error) {
	certStore, err := transport.NewCertStore(certDir)
	if err != nil {
		return nil, fmt.Errorf("cert store: %w", err)
	}
	bootCert, bootKey, err := loadOrCreateBootstrapIdentity(certStore)
	if err != nil {
		return nil, err
	}

	mgr, err := transport.NewManager(transport.Config{
		BootstrapAddr:    bootstrapAddr,
		MTLSAddr:         grpcAddr,
		CA:               authority,
		DeviceCertPEM:    certPEM,
		DeviceKeyPEM:     keyPEM,
		BootstrapCertPEM: bootCert,
		BootstrapKeyPEM:  bootKey,
		BootstrapTimeout: 0, // No timeout — keep bootstrap open for pairing.
		Logger:           logger,
		OnPeerAccepted:   buildOnPeerAccepted(logger, registry, cfg.Security.AutoAccept),
	})
	if err != nil {
		return nil, fmt.Errorf("init transport: %w", err)
	}
	return mgr, nil
}

// serve binds listeners, starts background monitors, and blocks until the
// context is cancelled or the gRPC server returns a fatal error.
func (d *daemon) serve(ctx context.Context) error {
	logger := d.logger

	// Start bootstrap listener for device pairing (regardless of mTLS state).
	if err := d.transportMgr.StartBootstrapOnly(ctx); err != nil {
		logger.Warn("could not start bootstrap port", "error", err)
	} else {
		d.addCleanup(func() { d.transportMgr.Stop() })
		bs := transport.NewBootstrapServer(d.transportMgr, version)
		go func() {
			if err := bs.Serve(ctx); err != nil && !errors.Is(err, context.Canceled) {
				logger.Error("bootstrap server stopped", "error", err)
			}
		}()
		logger.Info("bootstrap server started for pairing", "addr", d.bootstrapAddr)

		// Announce on the LAN so clients can find us with `sentinel discover`.
		// Best-effort: a failure (e.g. multicast blocked) must not stop the daemon.
		if d.discoveryEnabled {
			if adv, err := startDiscoveryAdvertiser(logger, d.deviceID, d.bootstrapAddr); err != nil {
				logger.Warn("could not start mDNS discovery", "error", err)
			} else {
				d.addCleanup(adv.Stop)
				logger.Info("mDNS discovery advertising", "service", "_sentinel._tcp", "addr", d.bootstrapAddr)
			}
		}
	}

	phase := "mtls"
	if d.transportMgr.BootstrapListener() != nil {
		phase = "mtls+bootstrap"
	}
	printStartupBanner(d.deviceID, d.grpcAddr, d.bootstrapAddr, phase, d.workerPool)

	startHeartbeatMonitor(ctx, d.sessionMgr, logger)

	healthMonitor := fleet.NewHealthMonitor(d.registry, d.certDir, logger, 60*time.Second)
	go healthMonitor.Start(ctx)

	metricsServer := startMetricsServer(logger, d.metricsAddr, d.workerPool)

	logger.Info("starting gRPC server", "addr", d.grpcAddr)
	errCh := make(chan error, 1)
	go func() {
		errCh <- d.grpcServer.Serve(d.grpcAddr)
	}()

	// Wait for shutdown signal or server error.
	select {
	case <-ctx.Done():
		logger.Info("shutting down...")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = metricsServer.Shutdown(shutdownCtx)
		d.grpcServer.Stop()
		return nil
	case err := <-errCh:
		return fmt.Errorf("gRPC server: %w", err)
	}
}

// setupLogging builds the daemon logger, preferring a rotating file writer and
// falling back to stderr when the log file cannot be opened. The returned close
// function flushes/closes the file writer (no-op for the stderr fallback).
func setupLogging(cfg *settings.Config) (*slog.Logger, func() error) {
	logPath := cfg.Logging.File
	if logPath == "" {
		logPath = datadir.LogPath()
	}
	maxSize := cfg.Logging.MaxSizeMB
	if maxSize == 0 {
		maxSize = 50
	}
	maxFiles := cfg.Logging.MaxFiles
	if maxFiles == 0 {
		maxFiles = 5
	}
	level := parseLogLevel(cfg.Logging.Level)

	logWriter, err := logrotate.New(logPath, maxSize, maxFiles)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "warning: failed to open log file %s: %v\n", logPath, err)
		return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})), func() error { return nil }
	}
	logger := slog.New(slog.NewJSONHandler(logWriter, &slog.HandlerOptions{Level: level}))
	return logger, logWriter.Close
}

// warnCertExpiry logs and prints a warning when the device certificate has
// expired or is close to expiring. Unparseable certificates are ignored.
func warnCertExpiry(logger *slog.Logger, certPEM []byte) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return
	}
	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
	switch {
	case daysLeft <= 0:
		logger.Error("device certificate has EXPIRED", "expired", cert.NotAfter.Format("2006-01-02"))
		_, _ = fmt.Fprintf(os.Stderr, "WARNING: Device certificate expired on %s! Run 'sentinel ca init' to renew.\n", cert.NotAfter.Format("2006-01-02"))
	case daysLeft <= 30:
		logger.Warn("device certificate expires soon", "days_left", daysLeft, "expires", cert.NotAfter.Format("2006-01-02"))
		_, _ = fmt.Fprintf(os.Stderr, "WARNING: Device certificate expires in %d days (%s)\n", daysLeft, cert.NotAfter.Format("2006-01-02"))
	}
}

// loadOrCreateBootstrapIdentity loads the persisted bootstrap identity or
// generates and persists a fresh one.
func loadOrCreateBootstrapIdentity(certStore *transport.CertStore) (certPEM, keyPEM []byte, err error) {
	if certStore.HasBootstrap() {
		certPEM, keyPEM, err = certStore.LoadBootstrap()
		if err != nil {
			return nil, nil, fmt.Errorf("load bootstrap identity: %w", err)
		}
		return certPEM, keyPEM, nil
	}
	certPEM, keyPEM, err = transport.GenerateBootstrapIdentity()
	if err != nil {
		return nil, nil, fmt.Errorf("generate bootstrap identity: %w", err)
	}
	if err := certStore.SaveBootstrap(certPEM, keyPEM); err != nil {
		return nil, nil, fmt.Errorf("save bootstrap identity: %w", err)
	}
	return certPEM, keyPEM, nil
}

// buildOnPeerAccepted returns the bootstrap peer-acceptance callback. When
// auto-accept is disabled, the peer is recorded as pending for manual approval.
func buildOnPeerAccepted(logger *slog.Logger, registry *fleet.Registry, autoAccept bool) func(string, []byte, string) (bool, error) {
	return func(peerID string, peerCert []byte, role string) (bool, error) {
		logger.Info("pairing request received", "peer_device_id", peerID, "requested_role", role)

		if autoAccept {
			logger.Info("auto-accepting peer", "device_id", peerID)
			return true, nil
		}

		if err := registry.AddPending(&fleet.Device{
			DeviceID: peerID,
			CertPEM:  peerCert,
			Role:     role,
		}); err != nil {
			logger.Error("failed to add pending device", "error", err)
			return false, err
		}

		logger.Info("device added to pending list — use 'sentinel pair accept' to approve", "device_id", peerID)
		// For now, auto-accept to complete the handshake.
		// In production, this would wait for manual approval.
		return true, nil
	}
}

// startHeartbeatMonitor periodically marks stale sessions until ctx is done.
func startHeartbeatMonitor(ctx context.Context, sessionMgr *session.Manager, logger *slog.Logger) {
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if n, err := sessionMgr.CheckStale(ctx, 30*time.Second); err == nil && n > 0 {
					logger.Info("marked stale sessions", "count", n)
				}
			}
		}
	}()
}

// startMetricsServer serves the Prometheus-style metrics endpoint on its own
// goroutine and returns the server so it can be shut down gracefully.
func startMetricsServer(logger *slog.Logger, addr string, pool *worker.Pool) *http.Server {
	handler := metrics.NewHandler(time.Now(), pool)
	mux := http.NewServeMux()
	mux.Handle("/metrics", handler)
	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		logger.Info("starting metrics server", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("metrics server failed", "error", err)
		}
	}()
	return srv
}

// startDiscoveryAdvertiser announces this daemon on the LAN via mDNS so peers
// can find it with `sentinel discover`. The bootstrap port is advertised
// because that is the entry point an unpaired client connects to.
func startDiscoveryAdvertiser(logger *slog.Logger, deviceID, bootstrapAddr string) (*discovery.Advertiser, error) {
	_, portStr, err := net.SplitHostPort(bootstrapAddr)
	if err != nil {
		return nil, fmt.Errorf("parse bootstrap addr %q: %w", bootstrapAddr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("parse bootstrap port %q: %w", portStr, err)
	}
	hostname, _ := os.Hostname()
	adv, err := discovery.NewAdvertiser(deviceID, hostname, version, port, logger)
	if err != nil {
		return nil, err
	}
	if err := adv.Start(); err != nil {
		return nil, err
	}
	return adv, nil
}

// registerServices registers every gRPC service on the server.
func registerServices(grpcServer *sentinelgrpc.Server, sb *sandbox.Sandbox, sessionMgr *session.Manager, pool *worker.Pool, logger *slog.Logger) {
	runner := exec.NewRunner(sb)
	fsSvc := fs.NewService(sb)
	payloadRegistry := payload.NewRegistry()

	grpcServer.RegisterExecService(sentinelgrpc.NewExecService(runner, sessionMgr, logger))
	grpcServer.RegisterFileSystemService(sentinelgrpc.NewFileSystemService(fsSvc, sessionMgr))
	grpcServer.RegisterSessionService(sentinelgrpc.NewSessionService(sessionMgr))
	grpcServer.RegisterPayloadService(sentinelgrpc.NewPayloadService(payloadRegistry))
	grpcServer.RegisterWorkerService(sentinelgrpc.NewWorkerService(pool))
	grpcServer.RegisterCaptureService(sentinelgrpc.NewCaptureService())
}

// orDefault returns v, or def when v is empty.
func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func printStartupBanner(deviceID, grpcAddr, bootstrapAddr, phase string, pool *worker.Pool) {
	hostname, _ := os.Hostname()
	localIPs := getLocalIPs()
	publicIP := getPublicIP()

	if serveJSON {
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
			PublicIP      string   `json:"public_ip"`
			StartedAt     string   `json:"started_at"`
			ActiveWorkers int      `json:"active_workers"`
			TotalWorkers  int      `json:"total_workers"`
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
			ActiveWorkers: pool.ActiveCount(),
			TotalWorkers:  pool.TotalCount(),
		}

		enc := json.NewEncoder(os.Stderr)
		enc.SetIndent("", "  ")
		_ = enc.Encode(info)
		return
	}

	// Default plain text output.
	localIP := "(none)"
	if len(localIPs) > 0 {
		localIP = localIPs[0]
	}

	_, _ = fmt.Fprintf(os.Stderr, `sentinel %s
hostname: %-20s os: %s/%s
grpc:     %-20s bootstrap: %s
device:   %s
local:    %-20s public: %s
phase:    %s
workers:  %d active, %d total
`, version,
		hostname, runtime.GOOS, runtime.GOARCH,
		grpcAddr, bootstrapAddr,
		deviceID,
		localIP, publicIP,
		phase,
		pool.ActiveCount(), pool.TotalCount(),
	)
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
	// Allow disabling the outbound lookup for air-gapped deployments and tests;
	// it otherwise makes external HTTP calls that can block startup.
	if os.Getenv("SENTINEL_SKIP_PUBLIC_IP") != "" {
		return "(disabled)"
	}

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
