package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/inovacc/sentinel/internal/ca"
	"github.com/inovacc/sentinel/internal/datadir"
	"github.com/inovacc/sentinel/internal/discovery"
	"github.com/inovacc/sentinel/pkg/transport"
	"github.com/spf13/cobra"
)

func newConnectCmd() *cobra.Command {
	var useDiscovery bool
	cmd := &cobra.Command{
		Use:   "connect [address]",
		Short: "Pair with a sentinel server (by address or via --discovery)",
		Long: `Pair this machine with a sentinel server over the bootstrap port.

  sentinel connect 192.168.1.5:7399        # pair with an explicit address
  sentinel connect --discovery             # find the server on the LAN via mDNS

If the server requires manual approval, this prints your device ID and the
command the admin must run, then you reconnect once approved.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			role, _ := cmd.Flags().GetString("role")

			var addr string
			switch {
			case useDiscovery:
				a, err := discoverServerAddr()
				if err != nil {
					return err
				}
				addr = a
			case len(args) == 1:
				addr = args[0]
			default:
				return fmt.Errorf("provide a server address (host:7399) or use --discovery")
			}

			err := runBootstrapConnect(addr, role)
			if err != nil && strings.Contains(err.Error(), "pending") {
				id := localBootstrapDeviceID()
				_, _ = fmt.Fprintf(os.Stderr,
					"\nServer requires approval. Your device ID:\n  %s\n\nAsk the admin to run:\n  sentinel pair accept %s\n\nThen run 'sentinel connect' again.\n",
					id, id)
				return nil // pending is an expected outcome, not a failure
			}
			return err
		},
	}
	cmd.Flags().StringP("role", "r", "operator", "Role to request: admin, operator, reader")
	cmd.Flags().BoolVar(&useDiscovery, "discovery", false, "Find the server on the LAN via mDNS instead of giving an address")
	return cmd
}

// discoverServerAddr scans the LAN for sentinel servers and returns one address.
func discoverServerAddr() (string, error) {
	scanner := discovery.NewScanner()
	devices, err := scanner.Scan(4 * time.Second)
	if err != nil {
		return "", fmt.Errorf("discovery scan: %w", err)
	}
	switch len(devices) {
	case 0:
		return "", fmt.Errorf("no sentinel servers found on the local network")
	case 1:
		_, _ = fmt.Fprintf(os.Stderr, "Discovered %s at %s\n", devices[0].DeviceID, devices[0].Address)
		return devices[0].Address, nil
	default:
		_, _ = fmt.Fprintln(os.Stderr, "Multiple servers found — re-run 'sentinel connect <address>' with one of:")
		for _, d := range devices {
			_, _ = fmt.Fprintf(os.Stderr, "  %s  (%s)\n", d.Address, d.DeviceID)
		}
		return "", fmt.Errorf("multiple servers found; specify an address")
	}
}

// localBootstrapDeviceID returns this machine's bootstrap device ID — the ID the
// server sees and that the admin approves with 'sentinel pair accept'.
func localBootstrapDeviceID() string {
	certDir, err := datadir.CertDir()
	if err != nil {
		return "(unknown)"
	}
	store, err := transport.NewCertStore(certDir)
	if err != nil || !store.HasBootstrap() {
		return "(unknown)"
	}
	certPEM, _, err := store.LoadBootstrap()
	if err != nil {
		return "(unknown)"
	}
	id, _ := ca.DeviceID(certPEM)
	return id
}
