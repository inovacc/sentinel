package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/inovacc/sentinel/internal/discovery"
	"github.com/spf13/cobra"
)

func newDiscoverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Scan LAN for sentinel instances via mDNS",
		Long:  `Performs an mDNS query on the local network to discover other sentinel instances.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			timeout, _ := cmd.Flags().GetDuration("timeout")

			scanner := discovery.NewScanner()
			devices, err := scanner.Scan(timeout)
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}

			if len(devices) == 0 {
				_, _ = fmt.Fprintln(os.Stderr, "no sentinel instances found on the local network")
				fmt.Println("[]")
				return nil
			}

			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(devices)
		},
	}

	cmd.Flags().Duration("timeout", 3*time.Second, "mDNS scan timeout")
	return cmd
}
