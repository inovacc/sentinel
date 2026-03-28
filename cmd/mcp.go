package cmd

import (
	"database/sql"
	"fmt"

	"github.com/inovacc/sentinel/internal/datadir"
	"github.com/inovacc/sentinel/internal/exec"
	"github.com/inovacc/sentinel/internal/fs"
	sentinelmcp "github.com/inovacc/sentinel/internal/mcp"
	"github.com/inovacc/sentinel/internal/sandbox"
	"github.com/inovacc/sentinel/internal/session"
	"github.com/inovacc/sentinel/internal/settings"
	"github.com/spf13/cobra"

	_ "modernc.org/sqlite"
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
			return runMCP(cmd)
		},
	}
}

func runMCP(cmd *cobra.Command) error {
	// Load configuration.
	cfg, err := settings.Load(datadir.ConfigPath())
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Initialize sandbox.
	sandboxRoot := cfg.Sandbox.Root
	if sandboxRoot == "" {
		sandboxRoot, _ = datadir.SandboxRoot()
	}

	sb, err := sandbox.New(sandbox.Config{
		Root:            sandboxRoot,
		ReadPatterns:    cfg.Sandbox.Allowlist.Read,
		ExecAllowlist:   cfg.Sandbox.Allowlist.Exec,
		BlockedCommands: cfg.Sandbox.Allowlist.BlockedCommands,
	})
	if err != nil {
		return fmt.Errorf("init sandbox: %w", err)
	}

	// Initialize database.
	db, err := sql.Open("sqlite", datadir.DBPath())
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() { _ = db.Close() }()

	// Initialize services.
	runner := exec.NewRunner(sb)
	fsSvc := fs.NewService(sb)
	sessionMgr, err := session.NewManager(db)
	if err != nil {
		return fmt.Errorf("init session manager: %w", err)
	}

	// Create and run MCP server.
	server := sentinelmcp.NewServer(runner, fsSvc, sessionMgr)
	return server.Run(cmd.Context())
}
