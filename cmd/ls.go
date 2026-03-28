package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/inovacc/sentinel/internal/client"
	"github.com/inovacc/sentinel/internal/datadir"
	"github.com/spf13/cobra"
)

func newLsCmd() *cobra.Command {
	lsCmd := &cobra.Command{
		Use:   "ls [device-id] [path]",
		Short: "List directory contents on a remote device",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			deviceID := args[0]
			path := "."
			if len(args) > 1 {
				path = args[1]
			}
			recursive, _ := cmd.Flags().GetBool("recursive")

			certDir, err := datadir.CertDir()
			if err != nil {
				return fmt.Errorf("cert dir: %w", err)
			}

			addr, err := client.ResolveDevice(deviceID, datadir.DBPath())
			if err != nil {
				return fmt.Errorf("resolve device: %w", err)
			}

			c, err := client.ConnectFromStore(addr, certDir)
			if err != nil {
				return fmt.Errorf("connect: %w", err)
			}
			defer func() { _ = c.Close() }()

			entries, err := c.ListDir(cmd.Context(), path, recursive)
			if err != nil {
				return fmt.Errorf("list dir: %w", err)
			}

			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(entries)
		},
	}
	lsCmd.Flags().BoolP("recursive", "r", false, "List recursively")
	return lsCmd
}
