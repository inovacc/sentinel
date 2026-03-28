package serverinfo

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const pidFileName = "sentinel.pid"

// WritePID writes the current process ID to sentinel.pid in the given directory.
func WritePID(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create pid dir: %w", err)
	}
	pid := os.Getpid()
	data := []byte(strconv.Itoa(pid))
	path := filepath.Join(dir, pidFileName)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write pid file: %w", err)
	}
	return nil
}

// ReadPID reads the PID from sentinel.pid in the given directory.
func ReadPID(dir string) (int, error) {
	path := filepath.Join(dir, pidFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read pid file: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("parse pid: %w", err)
	}
	return pid, nil
}

// RemovePID removes the sentinel.pid file from the given directory.
func RemovePID(dir string) error {
	path := filepath.Join(dir, pidFileName)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove pid file: %w", err)
	}
	return nil
}

// IsRunning checks if a sentinel process is running by reading the PID file
// and checking if the process is alive.
func IsRunning(dir string) bool {
	pid, err := ReadPID(dir)
	if err != nil {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Unix, FindProcess always succeeds. We send signal 0 to check liveness.
	// On Windows, FindProcess fails if the process doesn't exist.
	return isProcessAlive(proc)
}
