package cmd

import (
	"github.com/spf13/cobra"
)

var (
	cfgFile string
)

var rootCmd = &cobra.Command{
	Use:   "sentinel",
	Short: "Secure remote REPL daemon for Claude Code",
	Long: `Sentinel is a secure, non-destructive REPL daemon that lets Claude Code
remotely access machines across a fleet using mTLS authentication and
sandbox-enforced operations.`,
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: ~/.sentinel/config.yaml)")

	rootCmd.AddCommand(
		newServeCmd(),
		newServerCmd(),
		newBootstrapCmd(),
		newPairCmd(),
		newFleetCmd(),
		newExecCmd(),
		newUploadCmd(),
		newCaptureCmd(),
		newCACmd(),
		newMCPCmd(),
		newDiscoverCmd(),
		newVersionCmd(),
	)
}

