package settings

import (
	"fmt"
	"net"
	"os"

	"gopkg.in/yaml.v3"
)

// CurrentConfigVersion is the schema version written by this build. Bump it
// whenever the config layout changes and add a step to Config.Migrate.
const CurrentConfigVersion = 2

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
	// (No confine back-fill is needed: Load supplies the v2 defaults for files
	// that predate the confine: block. fromVersion is retained for the future
	// field-level migrations described above. See the doc comment.)
	if c.Version < CurrentConfigVersion {
		c.Version = CurrentConfigVersion
		changed = true
	}
	return changed
}
