package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/claymod/claymod/internal/libs"
	"github.com/claymod/claymod/internal/pkl"
	"github.com/claymod/claymod/internal/playbook"
	"github.com/claymod/claymod/internal/schema"
)

// addModulePathFlag declares the --module-path flag shared by the
// playbook subcommands (extra directories searched for modulepath: URIs,
// on top of the std and CLAYMOD_MODULE_PATH).
func addModulePathFlag(cmd *cobra.Command, p *[]string) {
	cmd.Flags().StringArrayVar(p, "module-path", nil,
		"extra directory searched for modulepath: URIs (repeatable; CLAYMOD_MODULE_PATH adds colon-separated ones)")
}

// resolveModulePath builds the module path for playbookFile: the std
// (embedded or CLAYMOD_SCHEMA_DIR), the environment and flag dirs, and
// — when a claymod.project.yaml exists above the playbook — the
// project's schemaPaths and synced git libraries.
func resolveModulePath(playbookFile string, flagDirs []string) ([]string, error) {
	return libs.ModulePathFor(playbookFile, append(schema.ExtraFromEnv(), flagDirs...), false)
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
	var extraPaths []string
	cmd := &cobra.Command{
		Use:   "validate <playbook.pkl>",
		Short: "Validate a playbook (schema, names, deps, cycles)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pb, err := loadPlaybook(cmd, args[0], extraPaths)
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
	addModulePathFlag(cmd, &extraPaths)
	return cmd
}

func newPlaybookPlanCmd() *cobra.Command {
	var host string
	var asJSON bool
	var extraPaths []string
	cmd := &cobra.Command{
		Use:   "plan <playbook.pkl>",
		Short: "Print the execution plan for a playbook",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pb, err := loadPlaybook(cmd, args[0], extraPaths)
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
	addModulePathFlag(cmd, &extraPaths)
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
// the result into the typed model. The schema (std) resolves from the
// embedded copy or CLAYMOD_SCHEMA_DIR — never from the working
// directory; flagDirs (--module-path) add extra lookup directories.
func loadPlaybook(cmd *cobra.Command, playbookFile string, flagDirs []string) (*playbook.Playbook, error) {
	absPath, err := filepath.Abs(playbookFile)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(absPath); err != nil {
		return nil, fmt.Errorf("playbook not found: %s", playbookFile)
	}
	dirs, err := resolveModulePath(absPath, flagDirs)
	if err != nil {
		return nil, err
	}
	ev := pkl.New()
	if !ev.Available() {
		return nil, pkl.ErrPklNotFound
	}
	raw, err := ev.Evaluate(cmd.Context(), absPath, pkl.EvalOptions{
		ModulePath: dirs,
	})
	if err != nil {
		return nil, modulePathError(err, dirs)
	}
	pb, err := playbook.Parse(raw)
	if err != nil {
		return nil, err
	}
	return pb, nil
}

// modulePathError annotates pkl module-resolution failures with the
// module path that was searched, so a missing module points at where
// the std and extra dirs actually came from.
func modulePathError(err error, dirs []string) error {
	msg := err.Error()
	if !strings.Contains(msg, "modulepath:") {
		return err
	}
	return fmt.Errorf("%w\nsearched module path: %s", err, strings.Join(dirs, string(os.PathListSeparator)))
}
