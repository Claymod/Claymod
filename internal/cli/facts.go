package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/claymod/claymod/internal/config"
	"github.com/claymod/claymod/internal/inventory"
	"github.com/claymod/claymod/internal/proto"
	"github.com/claymod/claymod/internal/state"
)

func newHostFactsCmd() *cobra.Command {
	var (
		dataDir       string
		inventoryPath string
		agentPort     int
		cached        bool
		asJSON        bool
	)
	cmd := &cobra.Command{
		Use:   "facts <hostname>",
		Short: "Show a host's facts (live, or cached from the inventory)",
		Long: `Facts dials the host's agent over mTLS and reports what it
knows about itself (hostname, OS, architecture, kernel). With --cached
it prints the facts recorded in the inventory instead (no network).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runHostFacts(cmd.Context(), cmd, args[0], hostFactsOptions{
				dataDir:       dataDir,
				inventoryPath: inventoryPath,
				agentPort:     agentPort,
				cached:        cached,
				asJSON:        asJSON,
			})
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", "claymod-data", "server data directory (control identity)")
	cmd.Flags().StringVar(&inventoryPath, "inventory", "", "inventory database (default: <data-dir>/inventory.db)")
	cmd.Flags().IntVar(&agentPort, "agent-port", 2323, "agent port on the WireGuard overlay")
	cmd.Flags().BoolVar(&cached, "cached", false, "print cached facts from the inventory (no network)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print facts as JSON")
	return cmd
}

type hostFactsOptions struct {
	dataDir       string
	inventoryPath string
	agentPort     int
	cached        bool
	asJSON        bool
}

func runHostFacts(ctx context.Context, cmd *cobra.Command, hostname string, o hostFactsOptions) error {
	out := cmd.OutOrStdout()
	cfg, err := config.LoadServer("")
	if err != nil {
		return err
	}
	if o.dataDir != "" {
		cfg.DataDir = o.dataDir
	}
	invPath := o.inventoryPath
	if invPath == "" {
		invPath = filepath.Join(cfg.DataDir, "inventory.db")
	}
	inv, err := inventory.Open(invPath, cfg.AgentNetwork)
	if err != nil {
		return err
	}
	defer inv.Close()

	host, err := inv.GetHost(hostname)
	if err != nil {
		return fmt.Errorf("resolve host %s: %w", hostname, err)
	}

	var facts proto.FactsResult
	source := "live"
	if o.cached {
		if err := json.Unmarshal([]byte(host.Facts), &facts); err != nil {
			return fmt.Errorf("parse cached facts for %s: %w", hostname, err)
		}
		source = "cached"
	} else {
		ctrl, err := state.LoadControlIdentity(cfg.DataDir)
		if err != nil {
			return err
		}
		conn, err := proto.Dial(
			fmt.Sprintf("%s:%d", host.WGIP, o.agentPort),
			hostname, ctrl.Identity, ctrl.ServerPool)
		if err != nil {
			return fmt.Errorf("dial %s: %w", hostname, err)
		}
		defer conn.Close()
		rpcErr, err := conn.Call(proto.Request{ID: "facts-1", Method: proto.MethodFacts}, &facts)
		if err != nil {
			return fmt.Errorf("facts from %s: %w", hostname, err)
		}
		if rpcErr != nil {
			return rpcErr
		}
	}

	if o.asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(facts)
	}
	fmt.Fprintf(out, "%-20s %-8s host=%s os=%s arch=%s kernel=%s\n",
		hostname, "("+source+")", facts.Hostname, facts.OS, facts.Arch, facts.Kernel)
	for k, v := range facts.Extra {
		fmt.Fprintf(out, "  %-18s %s\n", k+":", v)
	}
	return nil
}
