//go:build !windows

package supervisor

import (
	"os"
	"os/signal"
	"syscall"
)

func registerSignals(ch chan<- os.Signal) {
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
}

func signalProcess(p *os.Process, sig os.Signal) {
	_ = p.Signal(sig)
}
