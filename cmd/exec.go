package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newExecCmd() *cobra.Command {
	execCmd := &cobra.Command{
		Use:   "exec [device-id] [command...]",
		Short: "Execute a command on a remote device",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			deviceID := args[0]
			command := args[1:]
			stream, _ := cmd.Flags().GetBool("stream")

			fmt.Printf("Executing on %s: %v (stream=%v)\n", deviceID, command, stream)
			// TODO: Connect to device via gRPC, call ExecService.Exec or ExecStream
			return nil
		},
	}

	execCmd.Flags().BoolP("stream", "s", false, "Stream output in real-time")
	execCmd.Flags().IntP("timeout", "t", 30, "Command timeout in seconds")

	return execCmd
}
