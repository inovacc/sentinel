package cmd

import (
	"fmt"
	"os"
	osexec "os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/inovacc/sentinel/internal/datadir"
	"github.com/inovacc/sentinel/internal/serverinfo"
	"github.com/spf13/cobra"
)

func newServerCmd() *cobra.Command {
	serverCmd := &cobra.Command{
		Use:   "server",
		Short: "Manage the sentinel daemon as a service",
	}

	serverCmd.AddCommand(
		newServerInstallCmd(),
		newServerStartCmd(),
		newServerStopCmd(),
		newServerStatusCmd(),
	)

	return serverCmd
}

func newServerInstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install",
		Short: "Install sentinel as a system service",
		Long:  `On Windows: creates a scheduled task. On Linux: writes a systemd unit file.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			exe, err := os.Executable()
			if err != nil {
				return fmt.Errorf("resolve executable path: %w", err)
			}
			exe, err = filepath.EvalSymlinks(exe)
			if err != nil {
				return fmt.Errorf("resolve symlinks: %w", err)
			}

			switch runtime.GOOS {
			case "windows":
				return installWindows(exe)
			case "linux":
				return installLinux(exe)
			default:
				return fmt.Errorf("service install not supported on %s", runtime.GOOS)
			}
		},
	}
}

func newServerStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start the sentinel service",
		RunE: func(cmd *cobra.Command, args []string) error {
			switch runtime.GOOS {
			case "windows":
				out, err := osexec.Command("schtasks", "/Run", "/TN", "SentinelDaemon").CombinedOutput()
				if err != nil {
					return fmt.Errorf("start scheduled task: %w\n%s", err, string(out))
				}
				fmt.Println("sentinel service started via scheduled task")

			case "linux":
				out, err := osexec.Command("systemctl", "start", "sentinel").CombinedOutput()
				if err != nil {
					return fmt.Errorf("systemctl start: %w\n%s", err, string(out))
				}
				fmt.Println("sentinel service started")

			default:
				return fmt.Errorf("service start not supported on %s", runtime.GOOS)
			}
			return nil
		},
	}
}

func newServerStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stop the sentinel service",
		RunE: func(cmd *cobra.Command, args []string) error {
			switch runtime.GOOS {
			case "windows":
				return stopWindows()
			case "linux":
				out, err := osexec.Command("systemctl", "stop", "sentinel").CombinedOutput()
				if err != nil {
					return fmt.Errorf("systemctl stop: %w\n%s", err, string(out))
				}
				fmt.Println("sentinel service stopped")
			default:
				return fmt.Errorf("service stop not supported on %s", runtime.GOOS)
			}
			return nil
		},
	}
}

func newServerStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show sentinel service status",
		RunE: func(cmd *cobra.Command, args []string) error {
			switch runtime.GOOS {
			case "windows":
				return statusWindows()
			case "linux":
				out, err := osexec.Command("systemctl", "status", "sentinel").CombinedOutput()
				// systemctl status returns non-zero for inactive services,
				// which is informational, not an error.
				fmt.Println(string(out))
				if err != nil {
					// Only return error if the unit file doesn't exist.
					if strings.Contains(string(out), "could not be found") {
						return fmt.Errorf("sentinel service is not installed; run 'sentinel server install' first")
					}
				}
			default:
				return fmt.Errorf("service status not supported on %s", runtime.GOOS)
			}
			return nil
		},
	}
}

// --- Windows implementation ---

func installWindows(exePath string) error {
	// Create a scheduled task that runs "sentinel serve" at logon.
	out, err := osexec.Command("schtasks", "/Create",
		"/TN", "SentinelDaemon",
		"/TR", fmt.Sprintf(`"%s" serve`, exePath),
		"/SC", "ONLOGON",
		"/RL", "HIGHEST",
		"/F", // Force overwrite if exists.
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("create scheduled task: %w\n%s", err, string(out))
	}
	fmt.Println("sentinel installed as Windows scheduled task 'SentinelDaemon'")
	fmt.Println("  trigger: ONLOGON")
	fmt.Println("  command:", exePath, "serve")
	fmt.Println("  run 'sentinel server start' to start now")
	return nil
}

func stopWindows() error {
	// Read PID and kill the process.
	pid, err := serverinfo.ReadPID(datadir.Root())
	if err != nil {
		// Fallback: try to kill by image name.
		out, killErr := osexec.Command("taskkill", "/IM", "sentinel.exe", "/F").CombinedOutput()
		if killErr != nil {
			return fmt.Errorf("stop sentinel: no PID file and taskkill failed: %w\n%s", killErr, string(out))
		}
		fmt.Println("sentinel process killed by image name")
		return nil
	}

	out, err := osexec.Command("taskkill", "/PID", strconv.Itoa(pid), "/F").CombinedOutput()
	if err != nil {
		return fmt.Errorf("taskkill PID %d: %w\n%s", pid, err, string(out))
	}
	fmt.Printf("sentinel process (PID %d) stopped\n", pid)
	return nil
}

func statusWindows() error {
	running := serverinfo.IsRunning(datadir.Root())
	if running {
		pid, _ := serverinfo.ReadPID(datadir.Root())
		fmt.Printf("sentinel is running (PID %d)\n", pid)
	} else {
		fmt.Println("sentinel is not running")
	}

	// Also check the scheduled task.
	out, err := osexec.Command("schtasks", "/Query", "/TN", "SentinelDaemon", "/FO", "LIST").CombinedOutput()
	if err != nil {
		fmt.Println("scheduled task 'SentinelDaemon': not installed")
	} else {
		fmt.Println("\nscheduled task info:")
		fmt.Println(string(out))
	}
	return nil
}

// --- Linux implementation ---

const systemdUnit = `[Unit]
Description=Sentinel - Secure Remote REPL Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s serve
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`

func installLinux(exePath string) error {
	unitContent := fmt.Sprintf(systemdUnit, exePath)
	unitPath := "/etc/systemd/system/sentinel.service"

	if err := os.WriteFile(unitPath, []byte(unitContent), 0o644); err != nil {
		return fmt.Errorf("write systemd unit: %w (are you root?)", err)
	}

	// Reload systemd and enable.
	if out, err := osexec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w\n%s", err, string(out))
	}

	if out, err := osexec.Command("systemctl", "enable", "sentinel").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl enable: %w\n%s", err, string(out))
	}

	fmt.Println("sentinel installed as systemd service")
	fmt.Println("  unit file:", unitPath)
	fmt.Println("  command:", exePath, "serve")
	fmt.Println("  run 'sentinel server start' to start now")
	return nil
}
