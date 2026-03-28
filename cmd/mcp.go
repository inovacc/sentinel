package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newMCPCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Start MCP stdio server for Claude Code integration",
		Long: `Starts a Model Context Protocol server over stdio.
Claude Code connects to this to interact with the sentinel fleet.

Configure in ~/.claude/settings.json:
  {
    "mcpServers": {
      "sentinel": {
        "command": "sentinel",
        "args": ["mcp"]
      }
    }
  }`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Starting MCP stdio server...")
			// TODO: Initialize MCP server with go-sdk
			// TODO: Register tools: exec, read_file, write_file, list_dir, upload,
			//       glob, grep, screenshot, fleet_status, device_status,
			//       session.create, session.list, session.resume, session.pause,
			//       session.status, session.destroy
			// TODO: Run on stdio transport (blocks)
			return nil
		},
	}
}
