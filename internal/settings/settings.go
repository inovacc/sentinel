package settings

import (
	"fmt"
	"net"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// CurrentConfigVersion is the schema version written by this build. Bump it
// whenever the config layout changes and add a step to Config.Migrate.
const CurrentConfigVersion = 5

// Config holds all sentinel configuration.
type Config struct {
	Version   int             `yaml:"version"`
	Device    DeviceConfig    `yaml:"device"`
	Listen    ListenConfig    `yaml:"listen"`
	Security  SecurityConfig  `yaml:"security"`
	Sandbox   SandboxConfig   `yaml:"sandbox"`
	Fleet     FleetConfig     `yaml:"fleet"`
	Capture   CaptureConfig   `yaml:"capture"`
	Session   SessionConfig   `yaml:"session"`
	Logging   LoggingConfig   `yaml:"logging"`
	Discovery DiscoveryConfig `yaml:"discovery"`
	Confine   ConfineConfig   `yaml:"confine"`
	Audit     AuditConfig     `yaml:"audit"`
	Limits    LimitsConfig    `yaml:"limits"`
	Crypto    CryptoConfig    `yaml:"crypto"`
}

type DeviceConfig struct {
	Hostname string `yaml:"hostname"`
}

type ListenConfig struct {
	GRPC      string `yaml:"grpc"`
	Bootstrap string `yaml:"bootstrap"`
	Metrics   string `yaml:"metrics"`
}

type SecurityConfig struct {
	CADir      string `yaml:"ca_dir"`
	CertDir    string `yaml:"cert_dir"`
	AutoAccept bool   `yaml:"auto_accept"`
}

type SandboxConfig struct {
	Root      string          `yaml:"root"`
	MaxSizeGB int             `yaml:"max_size_gb"`
	Allowlist AllowlistConfig `yaml:"allowlist"`
}

type AllowlistConfig struct {
	Read            []string `yaml:"read"`
	Exec            []string `yaml:"exec"`
	BlockedCommands []string `yaml:"blocked_commands"`
}

type FleetConfig struct {
	Controller   string   `yaml:"controller"`
	KnownDevices []string `yaml:"known_devices"`
}

type CaptureConfig struct {
	ElectronPath   string  `yaml:"electron_path"`
	IPCPort        int     `yaml:"ipc_port"`
	DefaultQuality int     `yaml:"default_quality"`
	DefaultScale   float64 `yaml:"default_scale"`
}

type SessionConfig struct {
	HeartbeatInterval int  `yaml:"heartbeat_interval_seconds"`
	MaxIdleMinutes    int  `yaml:"max_idle_minutes"`
	CheckpointOnExec  bool `yaml:"checkpoint_on_exec"`
	CheckpointOnWrite bool `yaml:"checkpoint_on_write"`
}

type LoggingConfig struct {
	Level     string `yaml:"level"`
	Format    string `yaml:"format"`
	File      string `yaml:"file"`
	MaxSizeMB int    `yaml:"max_size_mb"`
	MaxFiles  int    `yaml:"max_files"`
}

// DiscoveryConfig controls LAN service discovery. When enabled, the daemon
// advertises itself via mDNS so peers can find it with `sentinel discover`.
type DiscoveryConfig struct {
	// Enabled announces this instance on the local network via mDNS.
	// It broadcasts the (public) device ID, hostname, and bootstrap port;
	// pairing still requires approval, so discovery only makes the server
	// findable. Disable on untrusted networks.
	Enabled bool `yaml:"enabled"`
	// WindowSeconds is how long the daemon advertises after each trigger
	// (startup and every lost connection) before going quiet again. Keeping
	// the window short limits how long the instance is broadcast on the LAN.
	// Defaults to 300 (5 minutes).
	WindowSeconds int `yaml:"window_seconds"`
}

// ConfineConfig controls OS-level process confinement (Windows v1).
type ConfineConfig struct {
	Enabled      bool   `yaml:"enabled"`
	MaxMemoryMB  uint64 `yaml:"max_memory_mb"`
	CPUPercent   uint32 `yaml:"cpu_percent"`
	MaxProcesses uint32 `yaml:"max_processes"`
}

// AuditConfig controls the security audit log (Phase 3.1).
type AuditConfig struct {
	Enabled       bool   `yaml:"enabled"`
	DBPath        string `yaml:"db_path"`        // empty = datadir default (audit.db)
	RetentionDays int    `yaml:"retention_days"` // 0 = keep forever
	SegmentMax    int    `yaml:"segment_max"`    // records per segment before seal
}

// LimitsConfig holds the resource-limit / DoS-protection knobs (Phase 3.2).
// Enabled (default true) gates the whole subsystem; the Proc* caps may be 0,
// meaning "unlimited — leave it to the OS default".
type LimitsConfig struct {
	Enabled bool `yaml:"enabled"`
	// T1.3 — bootstrap (pre-auth, per source IP).
	BootstrapPerIPMaxConns int `yaml:"bootstrap_per_ip_max_conns"`
	BootstrapPerIPRate     int `yaml:"bootstrap_per_ip_rate"`
	// T2.6 — mTLS listener.
	TLSHandshakeTimeout time.Duration `yaml:"tls_handshake_timeout"`
	MaxConns            int           `yaml:"max_conns"`
	PerDeviceMaxConns   int           `yaml:"per_device_max_conns"`
	// T2.4 — gRPC.
	MaxRecvMsgBytes      int    `yaml:"max_recv_msg_bytes"`
	MaxConcurrentStreams uint32 `yaml:"max_concurrent_streams"`
	RPCRatePerSec        int    `yaml:"rpc_rate_per_sec"`
	// T5.3 — process rlimits (Unix; complements the Windows Job Object).
	ProcMaxMemoryBytes uint64 `yaml:"proc_max_memory_bytes"` // RLIMIT_AS; 0 = unlimited
	ProcMaxOpenFiles   uint64 `yaml:"proc_max_open_files"`   // RLIMIT_NOFILE; 0 = unlimited
	ProcMaxCPUSeconds  uint64 `yaml:"proc_max_cpu_seconds"`  // RLIMIT_CPU; 0 = unlimited
}

// CryptoConfig controls CA-key-at-rest protection and cert lifetime (Phase 3.4).
type CryptoConfig struct {
	// KeyEncryption is one of: keystore | passphrase-env | passphrase-file | off.
	KeyEncryption  string        `yaml:"key_encryption"`
	PassphraseEnv  string        `yaml:"passphrase_env"`  // env var name (passphrase-env)
	PassphraseFile string        `yaml:"passphrase_file"` // path (passphrase-file)
	CertValidity   time.Duration `yaml:"cert_validity"`   // new device certs (default 720h)
	RenewThreshold time.Duration `yaml:"renew_threshold"` // auto-renew own cert under this (240h)
}

// maxCertValidity caps cert_validity to keep certs short-lived (T2.3).
const maxCertValidity = 90 * 24 * time.Hour

// defaultCryptoConfig is the single source of truth shared by DefaultConfig and
// Migrate so the two cannot drift.
func defaultCryptoConfig() CryptoConfig {
	return CryptoConfig{
		KeyEncryption:  "keystore",
		PassphraseEnv:  "SENTINEL_CA_PASSPHRASE",
		PassphraseFile: "",
		CertValidity:   720 * time.Hour,
		RenewThreshold: 240 * time.Hour,
	}
}

// defaultLimitsConfig is the single source of truth shared by DefaultConfig and
// Migrate so the two cannot drift.
func defaultLimitsConfig() LimitsConfig {
	return LimitsConfig{
		Enabled:                true,
		BootstrapPerIPMaxConns: 8,
		BootstrapPerIPRate:     5,
		TLSHandshakeTimeout:    10 * time.Second,
		MaxConns:               256,
		PerDeviceMaxConns:      16,
		MaxRecvMsgBytes:        1 << 20, // 1 MiB
		MaxConcurrentStreams:   128,
		RPCRatePerSec:          100,
		ProcMaxMemoryBytes:     1 << 30, // 1 GiB
		ProcMaxOpenFiles:       1024,
		ProcMaxCPUSeconds:      0,
	}
}

// defaultAuditConfig is the single source of truth for audit defaults, shared by
// DefaultConfig so the two cannot drift.
func defaultAuditConfig() AuditConfig {
	return AuditConfig{
		Enabled:       true,
		DBPath:        "",
		RetentionDays: 90,
		SegmentMax:    10000,
	}
}

// defaultConfineConfig returns the built-in confinement defaults. It is the
// single source of truth shared by DefaultConfig and Migrate so the two cannot
// drift when defaults change.
func defaultConfineConfig() ConfineConfig {
	return ConfineConfig{
		Enabled:      true,
		MaxMemoryMB:  1024,
		CPUPercent:   80,
		MaxProcesses: 64,
	}
}

// DefaultConfig returns a config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Version: CurrentConfigVersion,
		Listen: ListenConfig{
			GRPC:      ":7400",
			Bootstrap: ":7399",
			Metrics:   ":7401",
		},
		Security: SecurityConfig{
			AutoAccept: false,
		},
		Sandbox: SandboxConfig{
			MaxSizeGB: 10,
			Allowlist: AllowlistConfig{
				Exec: []string{"go", "git", "npm", "node", "python3", "python", "cargo", "make", "task", "scout", "sentinel", "omni", "unravel"},
				BlockedCommands: []string{
					"rm -rf /",
					"format",
					"fdisk",
					"mkfs",
					"dd if=",
				},
			},
		},
		Capture: CaptureConfig{
			IPCPort:        7402,
			DefaultQuality: 80,
			DefaultScale:   0.5,
		},
		Session: SessionConfig{
			HeartbeatInterval: 15,
			MaxIdleMinutes:    30,
			CheckpointOnExec:  true,
			CheckpointOnWrite: true,
		},
		Logging: LoggingConfig{
			Level:     "info",
			Format:    "json",
			MaxSizeMB: 50,
			MaxFiles:  5,
		},
		Discovery: DiscoveryConfig{
			Enabled:       true,
			WindowSeconds: 300,
		},
		Confine: defaultConfineConfig(),
		Audit:   defaultAuditConfig(),
		Limits:  defaultLimitsConfig(),
		Crypto:  defaultCryptoConfig(),
	}
}

// Validate checks the config for invalid values.
func (c *Config) Validate() error {
	// Check listen addresses are valid.
	if c.Listen.GRPC != "" {
		if _, _, err := net.SplitHostPort(c.Listen.GRPC); err != nil {
			return fmt.Errorf("invalid grpc listen address %q: %w", c.Listen.GRPC, err)
		}
	}
	// Check sandbox max size is reasonable.
	if c.Sandbox.MaxSizeGB < 0 {
		return fmt.Errorf("sandbox max_size_gb must be >= 0")
	}
	// Check log level is valid.
	switch c.Logging.Level {
	case "debug", "info", "warn", "error", "":
	default:
		return fmt.Errorf("invalid log level %q", c.Logging.Level)
	}
	// Check session heartbeat interval.
	if c.Session.HeartbeatInterval < 0 {
		return fmt.Errorf("session heartbeat_interval must be >= 0")
	}
	// Check confine CPU percentage is within range.
	if c.Confine.CPUPercent > 100 {
		return fmt.Errorf("confine.cpu_percent must be 0..100, got %d", c.Confine.CPUPercent)
	}
	// Check audit retention and segment bounds.
	if c.Audit.RetentionDays < 0 {
		return fmt.Errorf("audit.retention_days must be >= 0, got %d", c.Audit.RetentionDays)
	}
	if c.Audit.SegmentMax < 1 {
		return fmt.Errorf("audit.segment_max must be >= 1, got %d", c.Audit.SegmentMax)
	}
	// Check resource limits when the subsystem is enabled. The Proc* caps may be
	// 0 (meaning "unlimited"), so they are intentionally not checked here.
	if c.Limits.Enabled {
		if c.Limits.BootstrapPerIPMaxConns <= 0 {
			return fmt.Errorf("limits.bootstrap_per_ip_max_conns must be > 0, got %d", c.Limits.BootstrapPerIPMaxConns)
		}
		if c.Limits.BootstrapPerIPRate <= 0 {
			return fmt.Errorf("limits.bootstrap_per_ip_rate must be > 0, got %d", c.Limits.BootstrapPerIPRate)
		}
		if c.Limits.TLSHandshakeTimeout <= 0 {
			return fmt.Errorf("limits.tls_handshake_timeout must be > 0, got %v", c.Limits.TLSHandshakeTimeout)
		}
		if c.Limits.MaxConns <= 0 {
			return fmt.Errorf("limits.max_conns must be > 0, got %d", c.Limits.MaxConns)
		}
		if c.Limits.PerDeviceMaxConns <= 0 {
			return fmt.Errorf("limits.per_device_max_conns must be > 0, got %d", c.Limits.PerDeviceMaxConns)
		}
		if c.Limits.MaxRecvMsgBytes <= 0 {
			return fmt.Errorf("limits.max_recv_msg_bytes must be > 0, got %d", c.Limits.MaxRecvMsgBytes)
		}
		if c.Limits.MaxConcurrentStreams == 0 {
			return fmt.Errorf("limits.max_concurrent_streams must be > 0")
		}
		if c.Limits.RPCRatePerSec <= 0 {
			return fmt.Errorf("limits.rpc_rate_per_sec must be > 0, got %d", c.Limits.RPCRatePerSec)
		}
	}
	// Check crypto block (Phase 3.4).
	switch c.Crypto.KeyEncryption {
	case "keystore", "passphrase-env", "passphrase-file", "off":
	default:
		return fmt.Errorf("invalid crypto.key_encryption %q (want keystore|passphrase-env|passphrase-file|off)", c.Crypto.KeyEncryption)
	}
	if c.Crypto.KeyEncryption == "passphrase-env" && c.Crypto.PassphraseEnv == "" {
		return fmt.Errorf("crypto.passphrase_env is required for passphrase-env mode")
	}
	if c.Crypto.KeyEncryption == "passphrase-file" && c.Crypto.PassphraseFile == "" {
		return fmt.Errorf("crypto.passphrase_file is required for passphrase-file mode")
	}
	if c.Crypto.CertValidity <= 0 {
		return fmt.Errorf("crypto.cert_validity must be > 0, got %v", c.Crypto.CertValidity)
	}
	if c.Crypto.CertValidity > maxCertValidity {
		return fmt.Errorf("crypto.cert_validity must be <= %v, got %v", maxCertValidity, c.Crypto.CertValidity)
	}
	if c.Crypto.RenewThreshold <= 0 || c.Crypto.RenewThreshold >= c.Crypto.CertValidity {
		return fmt.Errorf("crypto.renew_threshold must satisfy 0 < threshold < cert_validity, got %v", c.Crypto.RenewThreshold)
	}
	return nil
}

// Load reads config from a YAML file, merging with defaults.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	return cfg, nil
}

// Save writes the config to a YAML file.
func Save(path string, cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return os.WriteFile(path, data, 0o600)
}

// OnDiskVersion returns the schema version recorded in the config file at path.
// It returns 0 (and a nil error) when the file is missing or has no version
// key — i.e. a pre-versioning config that should be migrated. A non-nil error
// means the file exists but could not be read or parsed.
func OnDiskVersion(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("read config: %w", err)
	}
	var probe struct {
		Version int `yaml:"version"`
	}
	if err := yaml.Unmarshal(data, &probe); err != nil {
		return 0, fmt.Errorf("parse config: %w", err)
	}
	return probe.Version, nil
}

// Migrate upgrades a loaded config to the current schema version in place,
// returning true if anything changed. fromVersion is the schema version recorded
// on disk (see OnDiskVersion); pass 0 for a pre-versioning or missing file.
//
// Migrate is deliberately thin: Load already overlays the on-disk YAML onto
// DefaultConfig, so any key absent from an older file (e.g. the whole confine:
// block introduced in v2) keeps its built-in default — there is nothing to back-
// fill here. Equally important, a v1 file that *does* set confine.enabled: false
// keeps that explicit choice through Load, and Migrate must not override it; that
// is why field-level changes are gated on fromVersion, never on whole-struct
// zero-ness, which would silently re-enable a security toggle the user disabled.
//
// This is where future field-level migrations (renames, moves) belong, each
// guarded by the on-disk fromVersion that introduced the change.
func (c *Config) Migrate(fromVersion int) bool {
	changed := false
	// v3 → v4 introduced the limits: block. Load overlays on-disk YAML onto
	// DefaultConfig, so a file written at v3 already carries the defaults for any
	// key it omits — but a file that wrote an explicit (zero-value) limits block,
	// or one with Enabled=false-by-omission, must be back-filled to the safe
	// defaults. Detect the unmigrated zero block and restore defaults.
	if fromVersion < 4 && c.Limits == (LimitsConfig{}) {
		c.Limits = defaultLimitsConfig()
		changed = true
	}
	// v4 → v5 introduced the crypto: block. A file written at v4 that omits it
	// already carries defaults via Load's overlay, but an explicit zero block
	// (or an unmigrated file) must be back-filled to the safe defaults.
	if fromVersion < 5 && c.Crypto == (CryptoConfig{}) {
		c.Crypto = defaultCryptoConfig()
		changed = true
	}
	if c.Version < CurrentConfigVersion {
		c.Version = CurrentConfigVersion
		changed = true
	}
	return changed
}
