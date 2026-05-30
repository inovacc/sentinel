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
		Use:   "exec [target] <command> [args...]",
		Short: "Execute a command on a sentinel daemon (local by default)",
		Long: `Execute a command on a sentinel daemon.

The optional leading target selects which daemon to run on; omit it for the
local daemon:

  sentinel exec go version                  # local daemon (this machine)
  sentinel exec 192.168.1.5:7400 go test    # a remote address
  sentinel exec <device-id> ls              # a paired device, by ID`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target, rest := client.SplitTarget(args)
			if len(rest) == 0 {
				return fmt.Errorf("no command specified")
			}
			command := rest[0]
			var cmdArgs []string
			if len(rest) > 1 {
				cmdArgs = rest[1:]
			}
			stream, _ := cmd.Flags().GetBool("stream")
			timeout, _ := cmd.Flags().GetInt("timeout")
			workDir, _ := cmd.Flags().GetString("workdir")
			bg, _ := cmd.Flags().GetBool("background")

			return runExec(target, command, cmdArgs, workDir, int32(timeout), stream, bg)
		},
	}

	execCmd.Flags().BoolP("stream", "s", false, "Stream output in real-time")
	execCmd.Flags().IntP("timeout", "t", 30, "Command timeout in seconds")
	execCmd.Flags().StringP("workdir", "w", "", "Working directory on the remote device")
	execCmd.Flags().BoolP("background", "b", false, "Start process in background (detached)")

	return execCmd
}

func runExec(target, command string, args []string, workDir string, timeout int32, stream, background bool) error {
	// Resolve the target to an address: local daemon, a host:port, or a device ID.
	addr, err := client.ResolveAddress(target)
	if err != nil {
		return fmt.Errorf("resolve target: %w", err)
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
	return runExecUnary(ctx, c, command, args, workDir, timeout, background, enc)
}

func runExecUnary(ctx context.Context, c *client.Client, command string, args []string, workDir string, timeout int32, background bool, enc *json.Encoder) error {
	resp, err := c.Exec(ctx, command, args, workDir, timeout, background)
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
