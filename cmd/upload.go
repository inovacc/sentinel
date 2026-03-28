package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/inovacc/sentinel/internal/client"
	"github.com/inovacc/sentinel/internal/datadir"
	"github.com/spf13/cobra"

	_ "modernc.org/sqlite"
)

func newUploadCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "upload [device-id] [local-path]",
		Short: "Upload a file to a device's sandbox",
		Long:  "Upload a local file to the remote device's sandbox directory via chunked gRPC streaming.",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			deviceID := args[0]
			localPath := args[1]
			remotePath, _ := cmd.Flags().GetString("remote-path")
			timeout, _ := cmd.Flags().GetInt("timeout")

			return runUpload(deviceID, localPath, remotePath, timeout)
		},
	}

	cmd.Flags().StringP("remote-path", "r", "", "Target path on the remote device (defaults to filename in sandbox)")
	cmd.Flags().IntP("timeout", "t", 120, "Upload timeout in seconds")

	return cmd
}

func runUpload(deviceID, localPath, remotePath string, timeout int) error {
	// Validate local file exists and is a regular file.
	info, err := os.Stat(localPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", localPath, err)
	}
	if info.IsDir() {
		return fmt.Errorf("directory upload not supported in v1; upload individual files instead")
	}

	// Read the local file.
	data, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", localPath, err)
	}

	// Default remote path to the base filename.
	if remotePath == "" {
		remotePath = filepath.Base(localPath)
	}

	// Resolve device address from fleet registry.
	addr, err := client.ResolveDevice(deviceID, datadir.DBPath())
	if err != nil {
		return fmt.Errorf("resolve device: %w", err)
	}

	// Connect via gRPC using mTLS certs.
	certDir, err := datadir.CertDir()
	if err != nil {
		return fmt.Errorf("cert dir: %w", err)
	}

	c, err := client.ConnectFromStore(addr, certDir)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	if err := c.Upload(ctx, remotePath, data); err != nil {
		return fmt.Errorf("upload: %w", err)
	}

	result := struct {
		Status     string `json:"status"`
		DeviceID   string `json:"device_id"`
		LocalPath  string `json:"local_path"`
		RemotePath string `json:"remote_path"`
		Bytes      int    `json:"bytes"`
	}{
		Status:     "uploaded",
		DeviceID:   deviceID,
		LocalPath:  localPath,
		RemotePath: remotePath,
		Bytes:      len(data),
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
