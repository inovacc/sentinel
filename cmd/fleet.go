package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newFleetCmd() *cobra.Command {
	fleetCmd := &cobra.Command{
		Use:   "fleet",
		Short: "Manage the device fleet",
	}

	fleetCmd.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "List all devices in the fleet",
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Println("Fleet devices:")
				// TODO: Query fleet registry, display table
				return nil
			},
		},
		&cobra.Command{
			Use:   "status [device-id]",
			Short: "Show detailed status for a device",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Printf("Status for device %s:\n", args[0])
				// TODO: Query device via gRPC Health
				return nil
			},
		},
		&cobra.Command{
			Use:   "remove [device-id]",
			Short: "Remove a device from the fleet",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Printf("Removing device %s from fleet\n", args[0])
				// TODO: Remove from registry, revoke certificate
				return nil
			},
		},
	)

	return fleetCmd
}
