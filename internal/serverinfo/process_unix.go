//go:build !windows

package serverinfo

import (
	"os"
	"syscall"
)

func isProcessAlive(p *os.Process) bool {
	err := p.Signal(syscall.Signal(0))
	return err == nil
}
