//go:build windows

package serverinfo

import (
	"os"
)

func isProcessAlive(p *os.Process) bool {
	// On Windows, os.FindProcess only succeeds if the process exists.
	// We attempt to signal 0 which is a no-op but validates the handle.
	// If that fails, we fall back to assuming it's alive since FindProcess succeeded.
	err := p.Signal(os.Signal(nil))
	// "os: process already finished" means dead; nil or access-denied means alive.
	return err == nil || err.Error() != "os: process already finished"
}
