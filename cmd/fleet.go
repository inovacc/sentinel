package cmd

import (
	"encoding/json"
	"fmt"
	"os"

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
				reg, cleanup, err := openRegistry()
				if err != nil {
					return err
				}
				defer cleanup()

				devices, err := reg.List("")
				if err != nil {
					return fmt.Errorf("list devices: %w", err)
				}

				if len(devices) == 0 {
					_, _ = fmt.Fprintln(os.Stderr, "No devices in fleet")
					return nil
				}

				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(devices)
			},
		},
		&cobra.Command{
			Use:   "status [device-id]",
			Short: "Show detailed status for a device",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				reg, cleanup, err := openRegistry()
				if err != nil {
					return err
				}
				defer cleanup()

				device, err := reg.Get(args[0])
				if err != nil {
					return fmt.Errorf("device not found: %w", err)
				}

				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(device)
			},
		},
		&cobra.Command{
			Use:   "remove [device-id]",
			Short: "Remove a device from the fleet",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				reg, cleanup, err := openRegistry()
				if err != nil {
					return err
				}
				defer cleanup()

				if err := reg.Remove(args[0]); err != nil {
					return fmt.Errorf("remove device: %w", err)
				}

				result := struct {
					Status   string `json:"status"`
					DeviceID string `json:"device_id"`
				}{
					Status:   "removed",
					DeviceID: args[0],
				}

				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(result)
			},
		},
	)

	return fleetCmd
}
