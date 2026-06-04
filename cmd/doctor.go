package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/inovacc/sentinel/internal/ca"
	"github.com/inovacc/sentinel/internal/datadir"
	sentinelcrypto "github.com/inovacc/sentinel/internal/security/crypto"
	"github.com/inovacc/sentinel/internal/settings"
	"github.com/spf13/cobra"
)

// docStatus is the outcome of a single doctor check.
type docStatus string

const (
	stOK    docStatus = "OK"
	stWarn  docStatus = "WARN"
	stFail  docStatus = "FAIL"
	stFixed docStatus = "FIXED"
)

type docResult struct {
	name   string
	status docStatus
	detail string
}

func newDoctorCmd() *cobra.Command {
	var fix bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose (and with --fix, repair) the sentinel installation",
		Long: `Checks the data directory, configuration (including schema-version
migration), certificate authority, device certificate, and listen ports.

By default it only reports. With --fix it applies safe repairs: creating missing
directories and writing or migrating the configuration file to the current
schema version. CA/certificate problems are reported with the command to run.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDoctor(cmd.OutOrStdout(), fix)
		},
	}
	cmd.Flags().BoolVar(&fix, "fix", false, "apply safe fixes (create dirs, write/migrate config)")
	return cmd
}

func runDoctor(w io.Writer, fix bool) error {
	results := []docResult{checkDataDir(fix)}

	cfgResult, cfg := checkConfig(fix)
	results = append(results, cfgResult, checkCA(), checkCAKeyAtRest(), checkDeviceCert(), checkPorts(cfg), checkFleetTrust())

	var ok, fixed, warns, fails int
	_, _ = fmt.Fprintf(w, "Sentinel Doctor  (data dir: %s)\n\n", datadir.Root())
	for _, r := range results {
		_, _ = fmt.Fprintf(w, "  [%-5s] %-22s %s\n", r.status, r.name, r.detail)
		switch r.status {
		case stOK:
			ok++
		case stFixed:
			fixed++
		case stWarn:
			warns++
		case stFail:
			fails++
		}
	}

	_, _ = fmt.Fprintf(w, "\n%d ok, %d fixed, %d warning(s), %d problem(s)\n", ok, fixed, warns, fails)
	if !fix && warns+fails > 0 {
		_, _ = fmt.Fprintln(w, "Run 'sentinel doctor --fix' to apply automatic repairs.")
	}
	if fails > 0 {
		return fmt.Errorf("doctor: %d unresolved problem(s)", fails)
	}
	return nil
}

// checkDataDir ensures the data directory and its subdirectories exist.
func checkDataDir(fix bool) docResult {
	const name = "data directory"
	root := datadir.Root()
	dirs := []string{root,
		filepath.Join(root, "ca"),
		filepath.Join(root, "certs"),
		filepath.Join(root, "sandbox"),
	}

	var missing []string
	for _, d := range dirs {
		if _, err := os.Stat(d); err != nil {
			missing = append(missing, d)
		}
	}
	if len(missing) == 0 {
		return docResult{name, stOK, "all directories present"}
	}
	if !fix {
		return docResult{name, stWarn, fmt.Sprintf("%d director(ies) missing", len(missing))}
	}
	for _, d := range missing {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return docResult{name, stFail, fmt.Sprintf("create %s: %v", d, err)}
		}
	}
	return docResult{name, stFixed, fmt.Sprintf("created %d director(ies)", len(missing))}
}

// checkConfig validates the daemon config file and migrates it to the current
// schema version. It returns the loaded (and possibly defaulted) config for reuse.
func checkConfig(fix bool) (docResult, *settings.Config) {
	return checkConfigAt(datadir.ConfigPath(), fix)
}

func checkConfigAt(path string, fix bool) (docResult, *settings.Config) {
	const name = "config"

	diskVer, err := settings.OnDiskVersion(path)
	if err != nil {
		return docResult{name, stFail, fmt.Sprintf("%v", err)}, settings.DefaultConfig()
	}
	cfg, err := settings.Load(path)
	if err != nil {
		return docResult{name, stFail, fmt.Sprintf("%v", err)}, settings.DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return docResult{name, stFail, fmt.Sprintf("invalid: %v", err)}, cfg
	}

	_, statErr := os.Stat(path)
	fileExists := statErr == nil

	switch {
	case !fileExists:
		if !fix {
			return docResult{name, stWarn, "no config file (using built-in defaults)"}, cfg
		}
		cfg.Migrate(diskVer)
		if err := settings.Save(path, cfg); err != nil {
			return docResult{name, stFail, fmt.Sprintf("write: %v", err)}, cfg
		}
		return docResult{name, stFixed, fmt.Sprintf("created config (v%d)", cfg.Version)}, cfg

	case diskVer < settings.CurrentConfigVersion:
		if !fix {
			return docResult{name, stWarn, fmt.Sprintf("schema v%d, current is v%d", diskVer, settings.CurrentConfigVersion)}, cfg
		}
		cfg.Migrate(diskVer)
		if err := settings.Save(path, cfg); err != nil {
			return docResult{name, stFail, fmt.Sprintf("write: %v", err)}, cfg
		}
		return docResult{name, stFixed, fmt.Sprintf("migrated v%d -> v%d", diskVer, settings.CurrentConfigVersion)}, cfg

	default:
		return docResult{name, stOK, fmt.Sprintf("v%d, valid", diskVer)}, cfg
	}
}

func checkCA() docResult {
	const name = "certificate authority"
	caDir := filepath.Join(datadir.Root(), "ca")
	if _, err := ca.Load(caDir); err != nil {
		return docResult{name, stFail, "not initialized — run 'sentinel ca init'"}
	}
	return docResult{name, stOK, "loaded"}
}

func checkDeviceCert() docResult {
	const name = "device certificate"
	certPEM, err := os.ReadFile(filepath.Join(datadir.Root(), "certs", "device.crt"))
	if err != nil {
		return docResult{name, stFail, "missing — run 'sentinel ca init'"}
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return docResult{name, stFail, "unreadable PEM"}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return docResult{name, stFail, fmt.Sprintf("parse: %v", err)}
	}
	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
	switch {
	case daysLeft <= 0:
		return docResult{name, stFail, "EXPIRED — run 'sentinel ca init'"}
	case daysLeft <= 30:
		return docResult{name, stWarn, fmt.Sprintf("expires in %d days — run 'sentinel ca init'", daysLeft)}
	default:
		return docResult{name, stOK, fmt.Sprintf("valid (%d days left)", daysLeft)}
	}
}

func checkPorts(cfg *settings.Config) docResult {
	const name = "listen ports"
	ports := [][2]string{
		{"grpc", cfg.Listen.GRPC},
		{"bootstrap", cfg.Listen.Bootstrap},
		{"metrics", cfg.Listen.Metrics},
	}
	var inUse []string
	for _, p := range ports {
		addr := p[1]
		if addr == "" {
			continue
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			inUse = append(inUse, fmt.Sprintf("%s %s", p[0], addr))
			continue
		}
		_ = ln.Close()
	}
	if len(inUse) == 0 {
		return docResult{name, stOK, "all available"}
	}
	return docResult{name, stWarn, "in use: " + strings.Join(inUse, ", ") + " (daemon already running?)"}
}

// checkCAKeyAtRest reports whether the CA key is encrypted, which mode protects
// it, and whether a plaintext backup lingers.
func checkCAKeyAtRest() docResult {
	const name = "CA key at rest"
	caDir := filepath.Join(datadir.Root(), "ca")
	keyPath := filepath.Join(caDir, "ca.key")
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return docResult{name, stWarn, "ca.key not found — run 'sentinel ca init'"}
	}
	bak := keyPath + ".plaintext.bak"
	if _, berr := os.Stat(bak); berr == nil {
		return docResult{name, stWarn, "encrypted, but a plaintext backup remains — securely delete ca.key.plaintext.bak"}
	}
	if sentinelcrypto.IsEnvelope(raw) {
		return docResult{name, stOK, "encrypted at rest"}
	}
	cfg, _ := settings.Load(datadir.ConfigPath())
	if cfg != nil && cfg.Crypto.KeyEncryption == "off" {
		return docResult{name, stWarn, "PLAINTEXT (crypto.key_encryption=off — dev only)"}
	}
	return docResult{name, stWarn, "PLAINTEXT — will be encrypted on next 'sentinel serve'"}
}
