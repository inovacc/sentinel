package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/inovacc/sentinel/internal/client"
	"github.com/inovacc/sentinel/internal/datadir"
	"github.com/spf13/cobra"
)

func newPayloadCmd() *cobra.Command {
	payloadCmd := &cobra.Command{
		Use:   "payload [device-id] [action] [json-payload]",
		Short: "Send a structured JSON payload to a remote device",
		Long: `Send a structured JSON request to a device and receive a JSON response.

Built-in actions: ping, sysinfo, env.get, echo, actions

Examples:
  sentinel payload <device-id> ping
  sentinel payload <device-id> sysinfo
  sentinel payload <device-id> echo '{"msg":"hello"}'
  sentinel payload <device-id> env.get '{"keys":["PATH","GOPATH"]}'`,
		Args: cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			deviceID := args[0]
			action := args[1]
			payload := ""
			if len(args) > 2 {
				payload = args[2]
			}

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

			resp, err := c.SendPayload(cmd.Context(), action, payload, nil)
			if err != nil {
				return fmt.Errorf("payload: %w", err)
			}

			// Pretty-print the response.
			output := struct {
				Action     string          `json:"action"`
				Success    bool            `json:"success"`
				Payload    json.RawMessage `json:"payload,omitempty"`
				Error      string          `json:"error,omitempty"`
				DurationMs int64           `json:"duration_ms"`
			}{
				Action:     resp.Action,
				Success:    resp.Success,
				DurationMs: resp.DurationMs,
			}

			if resp.Error != "" {
				output.Error = resp.Error
			}
			if resp.Payload != "" {
				output.Payload = json.RawMessage(resp.Payload)
			}

			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(output)
		},
	}
	return payloadCmd
}
