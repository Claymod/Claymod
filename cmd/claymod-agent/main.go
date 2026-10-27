// Command claymod-agent is the standalone host agent binary: a small
// static binary (agent + enrollment client + WireGuard setup) meant to
// be carried into or downloaded by hosts, including air-gapped ones.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/claymod/claymod/internal/agentcli"
)

// version is stamped by the build via -ldflags (see Makefile).
var version = "dev"

func main() {
	root := &cobra.Command{
		Use:           "claymod-agent",
		Short:         "claymod host agent (static, air-gap friendly)",
		Long:          "Small static host agent for claymod: enrolls with the control server over HTTPS and applies playbook ops over mTLS on the WireGuard overlay.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(agentcli.NewAgentCmd())
	root.AddCommand(agentcli.NewEnrollCmd())
	root.AddCommand(agentcli.NewWGSetupCmd())
	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the claymod-agent version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "claymod-agent %s\n", version)
		},
	})
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "claymod-agent:", err)
		os.Exit(1)
	}
}
