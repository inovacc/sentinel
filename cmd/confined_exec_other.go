//go:build !linux && !darwin

package cmd

import "fmt"

// runConfinedExec is never invoked on non-Unix platforms (the confiner there
// uses the Job Object, not the trampoline). The stub keeps the command
// registered so help output is uniform across builds.
func runConfinedExec(_ []string) error {
	return fmt.Errorf("confined-exec: rlimit trampoline is only supported on linux/darwin")
}
