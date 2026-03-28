package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newServeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Start the sentinel daemon (foreground)",
		Long:  `Starts the sentinel gRPC daemon in the foreground with supervisor pattern.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Starting sentinel daemon...")
			// TODO: Initialize supervisor (monitor + worker)
			// TODO: Start gRPC server with mTLS
			// TODO: Initialize session recovery (mark interrupted sessions)
			// TODO: Start health monitoring
			return nil
		},
	}
}
