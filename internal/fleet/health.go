package fleet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	v1 "github.com/inovacc/sentinel/internal/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// HealthMonitor periodically checks fleet device health.
type HealthMonitor struct {
	registry *Registry
	certDir  string
	logger   *slog.Logger
	interval time.Duration
}

// NewHealthMonitor creates a health monitor that pings fleet devices on an interval.
func NewHealthMonitor(registry *Registry, certDir string, logger *slog.Logger, interval time.Duration) *HealthMonitor {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	return &HealthMonitor{
		registry: registry,
		certDir:  certDir,
		logger:   logger,
		interval: interval,
	}
}

// Start begins the health monitoring loop. It blocks until ctx is cancelled.
func (h *HealthMonitor) Start(ctx context.Context) {
	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()

	h.logger.Info("fleet health monitor started", "interval", h.interval.String())

	for {
		select {
		case <-ctx.Done():
			h.logger.Info("fleet health monitor stopped")
			return
		case <-ticker.C:
			h.checkAll(ctx)
		}
	}
}

func (h *HealthMonitor) checkAll(ctx context.Context) {
	devices, err := h.registry.List(StatusOnline)
	if err != nil {
		h.logger.Error("health check: failed to list online devices", "error", err)
		return
	}

	if len(devices) == 0 {
		return
	}

	h.logger.Debug("health check: pinging devices", "count", len(devices))

	for _, d := range devices {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := h.pingDevice(d); err != nil {
			h.logger.Warn("health check: device unreachable, marking offline",
				"device_id", d.DeviceID,
				"address", d.Address,
				"error", err,
			)
			if err := h.registry.SetOffline(d.DeviceID); err != nil {
				h.logger.Error("health check: failed to set device offline",
					"device_id", d.DeviceID,
					"error", err,
				)
			}
		} else {
			h.logger.Debug("health check: device healthy",
				"device_id", d.DeviceID,
				"address", d.Address,
			)
			if err := h.registry.UpdateLastSeen(d.DeviceID); err != nil {
				h.logger.Error("health check: failed to update last seen",
					"device_id", d.DeviceID,
					"error", err,
				)
			}
		}
	}
}

func (h *HealthMonitor) pingDevice(d Device) error {
	if d.Address == "" {
		return fmt.Errorf("no address configured")
	}

	conn, err := h.dialDevice(d.Address)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer func() { _ = conn.Close() }()

	client := v1.NewPayloadServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := client.Send(ctx, &v1.PayloadRequest{
		Action: "ping",
	})
	if err != nil {
		return fmt.Errorf("ping: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("ping failed: %s", resp.Error)
	}

	return nil
}

func (h *HealthMonitor) dialDevice(addr string) (*grpc.ClientConn, error) {
	certPEM, err := os.ReadFile(filepath.Join(h.certDir, "device.crt"))
	if err != nil {
		return nil, fmt.Errorf("read client cert: %w", err)
	}

	keyPEM, err := os.ReadFile(filepath.Join(h.certDir, "device.key"))
	if err != nil {
		return nil, fmt.Errorf("read client key: %w", err)
	}

	caCertPEM, err := os.ReadFile(filepath.Join(h.certDir, "..", "ca", "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load client keypair: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	}

	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
	)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	return conn, nil
}
