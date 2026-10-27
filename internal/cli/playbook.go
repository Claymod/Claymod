package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/claymod/claymod/internal/pkl"
	"github.com/claymod/claymod/internal/playbook"
)

// schemaDir is where the shipped PKL schema lives relative to the
// repository root. For installed binaries the path is resolved at runtime
// from the CLAYMOD_SCHEMA_DIR environment variable, falling back to ./pkl.
func schemaDir() string {
	if v := os.Getenv("CLAYMOD_SCHEMA_DIR"); v != "" {
		return v
	}
	return "pkl"
}

func newPlaybookCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "playbook",
		Short: "Validate and plan PKL playbooks",
		Long: `Playbook commands evaluate a PKL playbook through the pkl CLI
(server-side) and check it before applying to hosts.`,
	}
	cmd.AddCommand(newPlaybookValidateCmd())
	cmd.AddCommand(newPlaybookPlanCmd())
	cmd.AddCommand(newPlaybookApplyCmd())
	return cmd
}

func newPlaybookValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate <playbook.pkl>",
		Short: "Validate a playbook (schema, names, deps, cycles)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pb, err := loadPlaybook(cmd, args[0])
			if err != nil {
				return err
			}
			if err := pb.Validate(); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "playbook OK: %d resource(s), %d host(s)\n",
				len(pb.Resources), len(pb.Hosts))
			return nil
		},
	}
}

func newPlaybookPlanCmd() *cobra.Command {
	var host string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "plan <playbook.pkl>",
		Short: "Print the execution plan for a playbook",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pb, err := loadPlaybook(cmd, args[0])
			if err != nil {
				return err
			}
			plan, err := pb.Plan(host)
			if err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(plan)
			}
			printPlan(cmd, plan)
			return nil
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "host to render for (sets the plan's Host)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the plan as JSON")
	return cmd
}

func printPlan(cmd *cobra.Command, plan *playbook.Plan) {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "plan for host %q (%d task(s)):\n", plan.Host, len(plan.Tasks))
	for _, task := range plan.Tasks {
		deps := ""
		if len(task.DependsOn) > 0 {
			deps = fmt.Sprintf(" (after %v)", task.DependsOn)
		}
		fmt.Fprintf(out, "  %d. %s [%s]%s\n", task.Index, task.Name, task.Type, deps)
	}
}

// loadPlaybook evaluates a PKL playbook through the pkl CLI and parses
// the result into the typed model.
func loadPlaybook(cmd *cobra.Command, playbookFile string) (*playbook.Playbook, error) {
	absPath, err := filepath.Abs(playbookFile)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(absPath); err != nil {
		return nil, fmt.Errorf("playbook not found: %s", playbookFile)
	}
	ev := pkl.New()
	if !ev.Available() {
		return nil, pkl.ErrPklNotFound
	}
	raw, err := ev.Evaluate(cmd.Context(), absPath, pkl.EvalOptions{
		ModulePath: []string{schemaDir()},
	})
	if err != nil {
		return nil, err
	}
	pb, err := playbook.Parse(raw)
	if err != nil {
		return nil, err
	}
	return pb, nil
}
