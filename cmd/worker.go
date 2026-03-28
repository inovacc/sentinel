package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/inovacc/sentinel/internal/client"
	"github.com/inovacc/sentinel/internal/datadir"
	"github.com/spf13/cobra"
)

func newWorkerCmd() *cobra.Command {
	workerCmd := &cobra.Command{
		Use:   "worker",
		Short: "Manage workers on a remote device",
	}

	workerCmd.AddCommand(
		newWorkerSpawnCmd(),
		newWorkerListCmd(),
		newWorkerGetCmd(),
		newWorkerKillCmd(),
		newWorkerKillAllCmd(),
	)

	return workerCmd
}

func newWorkerSpawnCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "spawn <device-id> <command...>",
		Short: "Spawn a new worker process on a remote device",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			deviceID := args[0]
			command := args[1]
			var cmdArgs []string
			if len(args) > 2 {
				cmdArgs = args[2:]
			}
			timeout, _ := cmd.Flags().GetInt("timeout")

			return runWorkerSpawn(deviceID, command, cmdArgs, int32(timeout))
		},
	}
	cmd.Flags().IntP("timeout", "t", 0, "Worker timeout in seconds (0 = no timeout)")
	return cmd
}

func newWorkerListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list <device-id>",
		Short: "List workers on a remote device",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			deviceID := args[0]
			statusFilter, _ := cmd.Flags().GetString("status")
			return runWorkerList(deviceID, statusFilter)
		},
	}
	cmd.Flags().String("status", "", "Filter by status (running, completed, failed, killed, stale)")
	return cmd
}

func newWorkerGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <device-id> <worker-id>",
		Short: "Get details for a specific worker",
		Args:  cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			return runWorkerGet(args[0], args[1])
		},
	}
}

func newWorkerKillCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "kill <device-id> <worker-id>",
		Short: "Kill a running worker",
		Args:  cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			return runWorkerKill(args[0], args[1])
		},
	}
}

func newWorkerKillAllCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "killall <device-id>",
		Short: "Kill all running workers on a remote device",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runWorkerKillAll(args[0])
		},
	}
}

func connectToDevice(deviceID string) (*client.Client, error) {
	addr, err := client.ResolveDevice(deviceID, datadir.DBPath())
	if err != nil {
		return nil, fmt.Errorf("resolve device: %w", err)
	}

	certDir, err := datadir.CertDir()
	if err != nil {
		return nil, fmt.Errorf("cert dir: %w", err)
	}

	return client.ConnectFromStore(addr, certDir)
}

func runWorkerSpawn(deviceID, command string, args []string, timeout int32) error {
	c, err := connectToDevice(deviceID)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := c.SpawnWorker(ctx, command, args, "", nil, "", nil, timeout)
	if err != nil {
		return fmt.Errorf("spawn worker: %w", err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(resp)
}

func runWorkerList(deviceID, statusFilter string) error {
	c, err := connectToDevice(deviceID)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := c.ListWorkers(ctx, statusFilter)
	if err != nil {
		return fmt.Errorf("list workers: %w", err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(resp)
}

func runWorkerGet(deviceID, workerID string) error {
	c, err := connectToDevice(deviceID)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	info, err := c.GetWorker(ctx, workerID)
	if err != nil {
		return fmt.Errorf("get worker: %w", err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(info)
}

func runWorkerKill(deviceID, workerID string) error {
	c, err := connectToDevice(deviceID)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := c.KillWorker(ctx, workerID); err != nil {
		return fmt.Errorf("kill worker: %w", err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{"killed": true, "worker_id": workerID})
}

func runWorkerKillAll(deviceID string) error {
	c, err := connectToDevice(deviceID)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	killed, err := c.KillAllWorkers(ctx)
	if err != nil {
		return fmt.Errorf("kill all workers: %w", err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{"killed_count": killed})
}
