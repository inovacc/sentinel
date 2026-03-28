package datadir

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

var (
	once sync.Once
	root string
)

// Root returns the sentinel data directory.
// On Unix: ~/.sentinel
// On Windows: %LOCALAPPDATA%\sentinel
func Root() string {
	once.Do(func() {
		if v := os.Getenv("SENTINEL_DATA_DIR"); v != "" {
			root = v
			return
		}
		switch runtime.GOOS {
		case "windows":
			root = filepath.Join(os.Getenv("LOCALAPPDATA"), "sentinel")
		default:
			home, _ := os.UserHomeDir()
			root = filepath.Join(home, ".sentinel")
		}
	})
	return root
}

// Sub returns a subdirectory under the data root, creating it if needed.
func Sub(name string) (string, error) {
	dir := filepath.Join(Root(), name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// SandboxRoot returns the sandbox directory path.
func SandboxRoot() (string, error) {
	return Sub("sandbox")
}

// CADir returns the CA directory path.
func CADir() (string, error) {
	return Sub("ca")
}

// CertDir returns the certificate directory path.
func CertDir() (string, error) {
	return Sub("certs")
}

// DBPath returns the path to the SQLite database.
func DBPath() string {
	return filepath.Join(Root(), "sentinel.db")
}

// ConfigPath returns the default config file path.
func ConfigPath() string {
	return filepath.Join(Root(), "config.yaml")
}

// LogPath returns the default log file path.
func LogPath() string {
	return filepath.Join(Root(), "sentinel.log")
}
