package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newPairCmd() *cobra.Command {
	pairCmd := &cobra.Command{
		Use:   "pair",
		Short: "Manage device pairing",
	}

	pairCmd.AddCommand(
		&cobra.Command{
			Use:   "accept [device-id]",
			Short: "Accept a pending pairing request",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				role, _ := cmd.Flags().GetString("role")
				fmt.Printf("Accepting device %s with role %s\n", args[0], role)
				// TODO: Sign device certificate, store in fleet registry
				return nil
			},
		},
		&cobra.Command{
			Use:   "reject [device-id]",
			Short: "Reject a pending pairing request",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Printf("Rejecting device %s\n", args[0])
				// TODO: Remove from pending list
				return nil
			},
		},
		&cobra.Command{
			Use:   "list",
			Short: "List pending pairing requests",
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Println("Pending pairing requests:")
				// TODO: Query fleet registry for pending devices
				return nil
			},
		},
	)

	acceptCmd := pairCmd.Commands()[0]
	acceptCmd.Flags().StringP("role", "r", "operator", "Role to assign: admin, operator, reader")

	return pairCmd
}
