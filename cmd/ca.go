package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newCACmd() *cobra.Command {
	caCmd := &cobra.Command{
		Use:   "ca",
		Short: "Certificate Authority management",
	}

	caCmd.AddCommand(
		&cobra.Command{
			Use:   "init",
			Short: "Initialize a new CA (generates root certificate and key)",
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Println("Initializing Certificate Authority...")
				// TODO: Generate P-256 ECDSA root CA
				// TODO: Store in CA directory
				// TODO: Generate device certificate signed by CA
				// TODO: Compute and display device ID
				return nil
			},
		},
		&cobra.Command{
			Use:   "show",
			Short: "Show CA and device certificate info",
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Println("CA Info:")
				// TODO: Display CA cert details, device ID, expiry
				return nil
			},
		},
		&cobra.Command{
			Use:   "export [output-dir]",
			Short: "Export CA certificate for sharing with other devices",
			Args:  cobra.MaximumNArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Println("Exporting CA certificate...")
				// TODO: Export CA cert (not key) for distribution
				return nil
			},
		},
		&cobra.Command{
			Use:   "sign [csr-path]",
			Short: "Sign a certificate signing request",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				role, _ := cmd.Flags().GetString("role")
				fmt.Printf("Signing CSR with role %s\n", role)
				// TODO: Sign CSR with CA, embed role in X.509 extension
				return nil
			},
		},
	)

	signCmd := caCmd.Commands()[3]
	signCmd.Flags().StringP("role", "r", "operator", "Role to embed: admin, operator, reader")

	return caCmd
}
