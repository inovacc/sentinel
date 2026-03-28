package svcutil

// Exit codes used by the supervisor and worker processes.
const (
	ExitOK      = 0
	ExitError   = 1
	ExitRestart = 3
	ExitUpgrade = 4
)
