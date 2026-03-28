package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var (
	// Set via ldflags at build time.
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print sentinel version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("sentinel %s\n", version)
			fmt.Printf("  commit: %s\n", commit)
			fmt.Printf("  built:  %s\n", date)
			fmt.Printf("  go:     %s\n", runtime.Version())
			fmt.Printf("  os:     %s/%s\n", runtime.GOOS, runtime.GOARCH)
		},
	}
}
