//go:build windows

package supervisor

import (
	"os"
	"os/signal"
)

func registerSignals(ch chan<- os.Signal) {
	signal.Notify(ch, os.Interrupt)
}

func signalProcess(p *os.Process, _ os.Signal) {
	// On Windows, the only reliable way to stop a process is to kill it.
	// os.Interrupt is not supported for sending to child processes.
	_ = p.Kill()
}
