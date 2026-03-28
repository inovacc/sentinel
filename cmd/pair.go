package cmd

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"

	"github.com/inovacc/sentinel/internal/ca"
	"github.com/inovacc/sentinel/internal/datadir"
	"github.com/inovacc/sentinel/internal/fleet"
	"github.com/spf13/cobra"

	_ "modernc.org/sqlite"
)

func newPairCmd() *cobra.Command {
	pairCmd := &cobra.Command{
		Use:   "pair",
		Short: "Manage device pairing",
	}

	pairCmd.AddCommand(
		newPairAcceptCmd(),
		newPairRejectCmd(),
		newPairListCmd(),
	)

	return pairCmd
}

func newPairAcceptCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "accept [device-id]",
		Short: "Accept a pending pairing request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			role, _ := cmd.Flags().GetString("role")
			return pairAccept(args[0], role)
		},
	}
	cmd.Flags().StringP("role", "r", "operator", "Role to assign: admin, operator, reader")
	return cmd
}

func newPairRejectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reject [device-id]",
		Short: "Reject a pending pairing request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return pairReject(args[0])
		},
	}
}

func newPairListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List pending pairing requests and trusted devices",
		RunE: func(cmd *cobra.Command, args []string) error {
			return pairList()
		},
	}
}

func openRegistry() (*fleet.Registry, func(), error) {
	db, err := sql.Open("sqlite", datadir.DBPath())
	if err != nil {
		return nil, nil, fmt.Errorf("open database: %w", err)
	}

	reg, err := fleet.NewRegistry(db)
	if err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("init fleet registry: %w", err)
	}

	return reg, func() { _ = db.Close() }, nil
}

func pairAccept(deviceID, role string) error {
	if !ca.ValidRole(role) {
		return fmt.Errorf("invalid role %q — use admin, operator, or reader", role)
	}

	reg, cleanup, err := openRegistry()
	if err != nil {
		return err
	}
	defer cleanup()

	// Verify device exists and is pending.
	device, err := reg.Get(deviceID)
	if err != nil {
		return fmt.Errorf("device %s not found in registry", deviceID)
	}

	if device.Status != fleet.StatusPending {
		return fmt.Errorf("device %s is not pending (status: %s)", deviceID, device.Status)
	}

	if err := reg.Accept(deviceID, role); err != nil {
		return fmt.Errorf("accept device: %w", err)
	}

	result := struct {
		Status   string `json:"status"`
		DeviceID string `json:"device_id"`
		Role     string `json:"role"`
		Hostname string `json:"hostname,omitempty"`
	}{
		Status:   "accepted",
		DeviceID: deviceID,
		Role:     role,
		Hostname: device.Hostname,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func pairReject(deviceID string) error {
	reg, cleanup, err := openRegistry()
	if err != nil {
		return err
	}
	defer cleanup()

	if err := reg.Reject(deviceID); err != nil {
		return fmt.Errorf("reject device: %w", err)
	}

	result := struct {
		Status   string `json:"status"`
		DeviceID string `json:"device_id"`
	}{
		Status:   "rejected",
		DeviceID: deviceID,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func pairList() error {
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
		_, _ = fmt.Fprintln(os.Stderr, "No devices in registry")
		return nil
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(devices)
}
