package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newUploadCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "upload [device-id] [local-path]",
		Short: "Upload a project to a device's sandbox",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			deviceID := args[0]
			localPath := args[1]

			fmt.Printf("Uploading %s to device %s sandbox\n", localPath, deviceID)
			// TODO: Chunked streaming upload via FileSystemService.Upload
			return nil
		},
	}
}
