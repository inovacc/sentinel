package cmd

import (
	"github.com/inovacc/sentinel/internal/confine"
	"github.com/spf13/cobra"
)

// newConfinedExecCmd builds the hidden re-exec trampoline. It is invoked by the
// Unix confiner (internal/confine): it sets RLIMIT_AS/NOFILE/CPU on itself, then
// exec's the real target so the limits are in force before the target starts.
// It is hidden because no human should run it directly.
func newConfinedExecCmd() *cobra.Command {
	return &cobra.Command{
		Use:                confine.TrampolineSubcommand + " [flags] -- command [args...]",
		Short:              "internal: apply process rlimits then exec a target (do not run directly)",
		Hidden:             true,
		DisableFlagParsing: true, // we parse --as/--nofile/--cpu/-- ourselves
		SilenceUsage:       true,
		RunE: func(_ *cobra.Command, args []string) error {
			return runConfinedExec(args)
		},
	}
}
