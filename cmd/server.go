package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newServerCmd() *cobra.Command {
	serverCmd := &cobra.Command{
		Use:   "server",
		Short: "Manage the sentinel daemon as a service",
	}

	serverCmd.AddCommand(
		&cobra.Command{
			Use:   "start",
			Short: "Start the daemon as a background service",
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Println("Starting sentinel service...")
				// TODO: Daemonize (platform-specific)
				return nil
			},
		},
		&cobra.Command{
			Use:   "stop",
			Short: "Stop the daemon service",
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Println("Stopping sentinel service...")
				// TODO: Send stop signal to running daemon
				return nil
			},
		},
		&cobra.Command{
			Use:   "status",
			Short: "Show daemon service status",
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Println("Checking sentinel status...")
				// TODO: Read PID file, check process
				return nil
			},
		},
		&cobra.Command{
			Use:   "install",
			Short: "Install as a system service (systemd/Windows SCM)",
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Println("Installing sentinel service...")
				// TODO: Platform-specific service installation
				return nil
			},
		},
	)

	return serverCmd
}
