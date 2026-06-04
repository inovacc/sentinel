package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/inovacc/sentinel/internal/clierr"
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
	// Runtime (RunE) failures should not print the usage block, and we print
	// the error ourselves through clierr so trust failures get an actionable
	// remediation instead of a raw x509 string.
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the root command, reporting any error with an actionable
// diagnostic on stderr.
func Execute() error {
	err := rootCmd.Execute()
	reportError(os.Stderr, err)
	return err
}

// reportError writes a classified, user-facing explanation of err to w. It is a
// no-op when err is nil.
func reportError(w io.Writer, err error) {
	if err == nil {
		return
	}
	_, _ = fmt.Fprintln(w, clierr.Explain(err))
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
		newWorkerCmd(),
		newPayloadCmd(),
		newLsCmd(),
		newUploadCmd(),
		newCaptureCmd(),
		newCACmd(),
		newMCPCmd(),
		newDiscoverCmd(),
		newConnectCmd(),
		newRenewCmd(),
		newRevokeCmd(),
		newUnrevokeCmd(),
		newDoctorCmd(),
		newVersionCmd(),
		newAuditCmd(),
		newConfinedExecCmd(),
	)
}
