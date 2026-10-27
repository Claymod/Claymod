// Package cli implements the claymod command tree.
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// version is stamped by the build via -ldflags (see Makefile).
var version = "dev"

// Execute runs the root command and returns its error to the caller; the
// caller decides how to exit (no os.Exit inside the library).
func Execute() error {
	return newRootCmd().Execute()
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "claymod",
		Short: "Push-based IaC over a WireGuard overlay",
		Long: `Claymod compiles PKL playbooks on a control server and applies
them to enrolled hosts over a WireGuard tunnel.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newVersionCmd())
	root.AddCommand(newAgentCmd())
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the claymod version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "claymod %s\n", version)
		},
	}
}
