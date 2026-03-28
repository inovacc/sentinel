package settings

import (
	"fmt"
	"net"
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds all sentinel configuration.
type Config struct {
	Device   DeviceConfig   `yaml:"device"`
	Listen   ListenConfig   `yaml:"listen"`
	Security SecurityConfig `yaml:"security"`
	Sandbox  SandboxConfig  `yaml:"sandbox"`
	Fleet    FleetConfig    `yaml:"fleet"`
	Capture  CaptureConfig  `yaml:"capture"`
	Session  SessionConfig  `yaml:"session"`
	Logging  LoggingConfig  `yaml:"logging"`
}

type DeviceConfig struct {
	Hostname string `yaml:"hostname"`
}

type ListenConfig struct {
	GRPC    string `yaml:"grpc"`
	Metrics string `yaml:"metrics"`
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
	ElectronPath   string `yaml:"electron_path"`
	IPCPort        int    `yaml:"ipc_port"`
	DefaultQuality int    `yaml:"default_quality"`
	DefaultScale   float64 `yaml:"default_scale"`
}

type SessionConfig struct {
	HeartbeatInterval int `yaml:"heartbeat_interval_seconds"`
	MaxIdleMinutes    int `yaml:"max_idle_minutes"`
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

// DefaultConfig returns a config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Listen: ListenConfig{
			GRPC:    ":7400",
			Metrics: ":7401",
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
