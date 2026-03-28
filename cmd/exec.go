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

	_ "modernc.org/sqlite"
)

func newExecCmd() *cobra.Command {
	execCmd := &cobra.Command{
		Use:   "exec [device-id] [command...]",
		Short: "Execute a command on a remote device",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			deviceID := args[0]
			command := args[1]
			var cmdArgs []string
			if len(args) > 2 {
				cmdArgs = args[2:]
			}
			stream, _ := cmd.Flags().GetBool("stream")
			timeout, _ := cmd.Flags().GetInt("timeout")
			workDir, _ := cmd.Flags().GetString("workdir")

			return runExec(deviceID, command, cmdArgs, workDir, int32(timeout), stream)
		},
	}

	execCmd.Flags().BoolP("stream", "s", false, "Stream output in real-time")
	execCmd.Flags().IntP("timeout", "t", 30, "Command timeout in seconds")
	execCmd.Flags().StringP("workdir", "w", "", "Working directory on the remote device")

	return execCmd
}

func runExec(deviceID, command string, args []string, workDir string, timeout int32, stream bool) error {
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

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second+5*time.Second)
	defer cancel()

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	if stream {
		return runExecStream(ctx, c, command, args, workDir, timeout, enc)
	}
	return runExecUnary(ctx, c, command, args, workDir, timeout, enc)
}

func runExecUnary(ctx context.Context, c *client.Client, command string, args []string, workDir string, timeout int32, enc *json.Encoder) error {
	resp, err := c.Exec(ctx, command, args, workDir, timeout)
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}

	result := struct {
		ExitCode   int32  `json:"exit_code"`
		Stdout     string `json:"stdout"`
		Stderr     string `json:"stderr"`
		DurationMs int64  `json:"duration_ms"`
	}{
		ExitCode:   resp.GetExitCode(),
		Stdout:     resp.GetStdout(),
		Stderr:     resp.GetStderr(),
		DurationMs: resp.GetDurationMs(),
	}

	return enc.Encode(result)
}

func runExecStream(ctx context.Context, c *client.Client, command string, args []string, workDir string, timeout int32, enc *json.Encoder) error {
	exitCode, err := c.ExecStream(ctx, command, args, workDir, timeout, func(stream string, data []byte) {
		switch stream {
		case "stderr":
			_, _ = fmt.Fprint(os.Stderr, string(data))
		default:
			_, _ = fmt.Fprint(os.Stdout, string(data))
		}
	})
	if err != nil {
		return fmt.Errorf("exec stream: %w", err)
	}

	// Print final exit code as JSON to stderr so it doesn't mix with streamed output.
	result := struct {
		ExitCode int32 `json:"exit_code"`
	}{
		ExitCode: exitCode,
	}
	encErr := json.NewEncoder(os.Stderr)
	encErr.SetIndent("", "  ")
	return encErr.Encode(result)
}
