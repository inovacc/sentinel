package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/inovacc/sentinel/internal/capture"
	"github.com/spf13/cobra"
)

func newCaptureCmd() *cobra.Command {
	captureCmd := &cobra.Command{
		Use:   "capture",
		Short: "Capture a screenshot from the local display",
		Long: `Captures a screenshot using OS-native tools.
On Windows: PowerShell + System.Drawing
On macOS: screencapture
On Linux: import (ImageMagick), gnome-screenshot, or scrot`,
		RunE: func(cmd *cobra.Command, args []string) error {
			output, _ := cmd.Flags().GetString("output")
			display, _ := cmd.Flags().GetInt("display")
			quality, _ := cmd.Flags().GetInt("quality")
			asJSON, _ := cmd.Flags().GetBool("json")

			data, format, err := capture.Screenshot(display, quality)
			if err != nil {
				return err
			}

			if asJSON {
				result := struct {
					Format string `json:"format"`
					Size   int    `json:"size"`
					Data   string `json:"data"`
				}{
					Format: format,
					Size:   len(data),
					Data:   base64.StdEncoding.EncodeToString(data),
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(result)
			}

			if output == "" {
				output = "screenshot." + format
			}

			if err := os.WriteFile(output, data, 0o644); err != nil {
				return fmt.Errorf("write screenshot: %w", err)
			}

			fmt.Printf("screenshot saved to %s (%s, %d bytes)\n", output, format, len(data))
			return nil
		},
	}

	captureCmd.Flags().StringP("output", "o", "", "Output file path (default: screenshot.<format>)")
	captureCmd.Flags().IntP("display", "d", 0, "Display index (0 = primary)")
	captureCmd.Flags().IntP("quality", "q", 0, "JPEG quality 1-99 (0 = PNG)")
	captureCmd.Flags().Bool("json", false, "Output as base64-encoded JSON")

	return captureCmd
}
