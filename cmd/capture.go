package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newCaptureCmd() *cobra.Command {
	captureCmd := &cobra.Command{
		Use:   "capture [device-id]",
		Short: "Capture a screenshot from a remote device",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			deviceID := args[0]
			output, _ := cmd.Flags().GetString("output")
			display, _ := cmd.Flags().GetInt("display")

			fmt.Printf("Capturing screenshot from device %s (display=%d, output=%s)\n", deviceID, display, output)
			// TODO: Call CaptureService.Screenshot via gRPC
			return nil
		},
	}

	captureCmd.Flags().StringP("output", "o", "screenshot.png", "Output file path")
	captureCmd.Flags().IntP("display", "d", 0, "Display index (0 = primary)")
	captureCmd.Flags().IntP("quality", "q", 80, "JPEG quality (0 = PNG)")

	return captureCmd
}
