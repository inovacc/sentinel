package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func newRevokeCmd() *cobra.Command {
	var reason string
	cmd := &cobra.Command{
		Use:   "revoke [device-id]",
		Short: "Revoke a device so its certificate is rejected at the mTLS handshake",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			reg, cleanup, err := openRegistryAudited()
			if err != nil {
				return err
			}
			defer cleanup()
			if err := reg.Revoke(args[0], reason); err != nil {
				return fmt.Errorf("revoke device: %w", err)
			}
			return emitJSON(struct {
				Status   string `json:"status"`
				DeviceID string `json:"device_id"`
				Reason   string `json:"reason,omitempty"`
			}{"revoked", args[0], reason})
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "", "reason for revocation (recorded in the audit log)")
	return cmd
}

func newUnrevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unrevoke [device-id]",
		Short: "Restore a previously revoked device",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			reg, cleanup, err := openRegistryAudited()
			if err != nil {
				return err
			}
			defer cleanup()
			if err := reg.Unrevoke(args[0]); err != nil {
				return fmt.Errorf("unrevoke device: %w", err)
			}
			return emitJSON(struct {
				Status   string `json:"status"`
				DeviceID string `json:"device_id"`
			}{"unrevoked", args[0]})
		},
	}
}

// emitJSON writes v as indented JSON to stdout (matches fleet command style).
func emitJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
