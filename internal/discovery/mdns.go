package discovery

import (
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/mdns"
)

const serviceName = "_sentinel._tcp"

// DiscoveredDevice represents a sentinel instance found on the LAN.
type DiscoveredDevice struct {
	DeviceID string `json:"device_id"`
	Hostname string `json:"hostname"`
	Address  string `json:"address"` // ip:port
	Version  string `json:"version"`
}

// Advertiser announces this sentinel instance on the LAN via mDNS.
type Advertiser struct {
	deviceID string
	hostname string
	port     int
	server   *mdns.Server
	logger   *slog.Logger
}

// NewAdvertiser creates an mDNS advertiser for this sentinel instance.
func NewAdvertiser(deviceID, hostname string, port int) (*Advertiser, error) {
	if deviceID == "" {
		return nil, fmt.Errorf("discovery: device ID is required")
	}
	if hostname == "" {
		return nil, fmt.Errorf("discovery: hostname is required")
	}
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("discovery: invalid port %d", port)
	}
	return &Advertiser{
		deviceID: deviceID,
		hostname: hostname,
		port:     port,
		logger:   slog.Default(),
	}, nil
}

// Start begins advertising this sentinel instance via mDNS.
func (a *Advertiser) Start() error {
	// Get local IPs for the mDNS record.
	ips := localIPv4s()

	info := []string{
		"device_id=" + a.deviceID,
		"version=" + version(),
	}

	service, err := mdns.NewMDNSService(
		a.hostname,    // instance name
		serviceName,   // service type
		"",            // domain (default: local.)
		"",            // host (auto-detect)
		a.port,        // port
		ips,           // IPs to announce
		info,          // TXT records
	)
	if err != nil {
		return fmt.Errorf("discovery: create mDNS service: %w", err)
	}

	server, err := mdns.NewServer(&mdns.Config{Zone: service})
	if err != nil {
		return fmt.Errorf("discovery: start mDNS server: %w", err)
	}

	a.server = server
	a.logger.Info("mDNS advertiser started",
		"device_id", a.deviceID,
		"hostname", a.hostname,
		"port", a.port,
		"service", serviceName,
	)
	return nil
}

// Stop stops the mDNS advertiser.
func (a *Advertiser) Stop() {
	if a.server != nil {
		if err := a.server.Shutdown(); err != nil {
			a.logger.Warn("mDNS advertiser shutdown error", "error", err)
		}
		a.server = nil
		a.logger.Info("mDNS advertiser stopped")
	}
}

// Scanner discovers sentinel instances on the LAN via mDNS.
type Scanner struct {
	logger *slog.Logger
}

// NewScanner creates a new mDNS scanner.
func NewScanner() *Scanner {
	return &Scanner{
		logger: slog.Default(),
	}
}

// Scan searches for sentinel instances on the LAN within the given timeout.
func (s *Scanner) Scan(timeout time.Duration) ([]DiscoveredDevice, error) {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	entriesCh := make(chan *mdns.ServiceEntry, 16)
	var devices []DiscoveredDevice

	done := make(chan struct{})
	go func() {
		defer close(done)
		for entry := range entriesCh {
			dev := parseEntry(entry)
			if dev.DeviceID != "" {
				devices = append(devices, dev)
				s.logger.Debug("discovered sentinel instance",
					"device_id", dev.DeviceID,
					"address", dev.Address,
				)
			}
		}
	}()

	params := mdns.DefaultParams(serviceName)
	params.Entries = entriesCh
	params.Timeout = timeout
	params.DisableIPv6 = true

	if err := mdns.Query(params); err != nil {
		close(entriesCh)
		return nil, fmt.Errorf("discovery: mDNS query failed: %w", err)
	}

	close(entriesCh)
	<-done

	return devices, nil
}

func parseEntry(entry *mdns.ServiceEntry) DiscoveredDevice {
	dev := DiscoveredDevice{
		Hostname: entry.Host,
	}

	// Build address from entry.
	ip := entry.AddrV4
	if ip == nil {
		ip = entry.AddrV6
	}
	if ip != nil {
		dev.Address = net.JoinHostPort(ip.String(), strconv.Itoa(entry.Port))
	}

	// Parse TXT records.
	for _, txt := range entry.InfoFields {
		if k, v, ok := strings.Cut(txt, "="); ok {
			switch k {
			case "device_id":
				dev.DeviceID = v
			case "version":
				dev.Version = v
			}
		}
	}

	return dev
}

func localIPv4s() []net.IP {
	var ips []net.IP
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ips
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
			ips = append(ips, ipNet.IP)
		}
	}
	return ips
}

// version returns the build version. This is set via ldflags in production.
// Falls back to "dev" if unset.
func version() string {
	return "dev"
}
