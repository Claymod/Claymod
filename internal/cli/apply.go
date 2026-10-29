package cli

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/claymod/claymod/internal/inventory"
	"github.com/claymod/claymod/internal/modules"
	_ "github.com/claymod/claymod/internal/modules/all" // register std compilers
	"github.com/claymod/claymod/internal/playbook"
	"github.com/claymod/claymod/internal/proto"
	"github.com/claymod/claymod/internal/runner"
	"github.com/claymod/claymod/internal/state"
)

// applyOptions configures one playbook apply run.
type applyOptions struct {
	dataDir       string
	inventoryPath string
	agentNetwork  string
	agentPort     int
	caFile        string
	certFile      string
	keyFile       string
	check         bool
	verbose       bool
	limit         string
	maxFail       int
	dialRetries   int
	parallel      int
	host          string
	modulePaths   []string
}

func newPlaybookApplyCmd() *cobra.Command {
	var o applyOptions
	cmd := &cobra.Command{
		Use:   "apply <playbook.pkl>",
		Short: "Apply a playbook to its hosts",
		Long: `Apply compiles a playbook per host (rendering templates with the
host's vars) and streams the primitive ops to each host's agent over the
framed mTLS protocol. Hosts are applied to in parallel.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runApply(cmd.Context(), cmd, args[0], o)
		},
	}
	cmd.Flags().StringVar(&o.dataDir, "data-dir", "claymod-data", "server data directory (default control identity and inventory)")
	cmd.Flags().StringVar(&o.inventoryPath, "inventory", "", "path to the inventory database (default: <data-dir>/inventory.db)")
	cmd.Flags().StringVar(&o.agentNetwork, "agent-network", "10.42.0.0/24", "agent overlay CIDR the inventory uses")
	cmd.Flags().IntVar(&o.agentPort, "agent-port", 2323, "agent port on the WireGuard overlay")
	cmd.Flags().StringVar(&o.caFile, "ca", "", "PEM file with the CA used to verify agents (default: <data-dir>/ca/ca.pem)")
	cmd.Flags().StringVar(&o.certFile, "cert", "", "PEM file with the control client certificate (default: <data-dir>/control.pem)")
	cmd.Flags().StringVar(&o.keyFile, "key", "", "PEM file with the control client key (default: <data-dir>/control-key.pem)")
	cmd.Flags().BoolVar(&o.check, "check", false, "report would-change without mutating hosts")
	cmd.Flags().BoolVarP(&o.verbose, "verbose", "v", false, "print per-op detail for every host")
	cmd.Flags().StringVar(&o.limit, "limit", "", "comma-separated hostnames to apply to (default: all targeted)")
	cmd.Flags().IntVar(&o.maxFail, "max-fail", 0, "failed hosts tolerated before skipping the rest (-1 = run all)")
	cmd.Flags().IntVar(&o.dialRetries, "dial-retries", 3, "connection setup retries per host (0 = dial once; mid-stream failures are never retried)")
	cmd.Flags().IntVar(&o.parallel, "parallel", runner.DefaultParallelism, "number of hosts applied to concurrently")
	cmd.Flags().StringVar(&o.host, "host", "", "render templates for this host (default: each target host)")
	addModulePathFlag(cmd, &o.modulePaths)
	return cmd
}

// runApply loads the playbook, resolves hosts from the inventory,
// compiles ops per host and runs them through the runner.
func runApply(ctx context.Context, cmd *cobra.Command, playbookFile string, o applyOptions) error {
	out := cmd.OutOrStdout()

	pb, err := loadPlaybook(cmd, playbookFile, o.modulePaths)
	if err != nil {
		return err
	}
	playbookDir := filepath.Dir(mustAbs(playbookFile))

	invPath := o.inventoryPath
	if invPath == "" {
		invPath = filepath.Join(o.dataDir, "inventory.db")
	}
	inv, err := inventory.Open(invPath, o.agentNetwork)
	if err != nil {
		return err
	}
	defer inv.Close()

	allHosts, err := inv.ListHosts()
	if err != nil {
		return err
	}
	if len(allHosts) == 0 {
		return fmt.Errorf("inventory has no hosts")
	}
	available := make([]string, 0, len(allHosts))
	for _, h := range allHosts {
		available = append(available, h.Hostname)
	}

	// Selection: playbook hosts, narrowed by --limit.
	targeted, err := playbook.ValidateHosts(pb.Hosts, available)
	if err != nil {
		return err
	}
	if o.limit != "" {
		wanted := map[string]bool{}
		for _, name := range strings.Split(o.limit, ",") {
			wanted[strings.TrimSpace(name)] = true
		}
		var narrowed []string
		for _, name := range targeted {
			if wanted[name] {
				narrowed = append(narrowed, name)
				delete(wanted, name)
			}
		}
		if len(wanted) > 0 {
			var missing []string
			for name := range wanted {
				missing = append(missing, name)
			}
			return fmt.Errorf("--limit names host(s) the playbook does not target: %s",
				strings.Join(missing, ", "))
		}
		targeted = narrowed
	}
	if len(targeted) == 0 {
		return fmt.Errorf("no hosts selected (playbook hosts: %s)", strings.Join(pb.Hosts, ", "))
	}

	var id proto.Identity
	var serverPool *x509.CertPool
	if o.caFile == "" && o.certFile == "" && o.keyFile == "" {
		// Default: the control identity created by `claymod serve`.
		ctrl, err := state.LoadControlIdentity(o.dataDir)
		if err != nil {
			return err
		}
		id, serverPool = ctrl.Identity, ctrl.ServerPool
	} else {
		if o.caFile == "" || o.certFile == "" || o.keyFile == "" {
			return fmt.Errorf("--ca, --cert and --key must be given together")
		}
		caPEM, err := os.ReadFile(o.caFile)
		if err != nil {
			return fmt.Errorf("read CA: %w", err)
		}
		serverPool, err = proto.CertPoolFromPEM(caPEM)
		if err != nil {
			return err
		}
		certPEM, err := os.ReadFile(o.certFile)
		if err != nil {
			return fmt.Errorf("read client cert: %w", err)
		}
		keyPEM, err := os.ReadFile(o.keyFile)
		if err != nil {
			return fmt.Errorf("read client key: %w", err)
		}
		id, err = proto.LoadIdentity(certPEM, keyPEM)
		if err != nil {
			return err
		}
	}

	// Compile per host: every host gets its own render context (hostName,
	// vars) so templates see the right data.
	specs := make([]runner.HostSpec, 0, len(targeted))
	for _, hostname := range targeted {
		h, err := inv.GetHost(hostname)
		if err != nil {
			return fmt.Errorf("resolve host %s: %w", hostname, err)
		}
		plan, err := pb.Plan(hostname)
		if err != nil {
			return err
		}
		renderHost := hostname
		if o.host != "" {
			// --host overrides the render hostname for every target
			// (consistent template output across hosts).
			renderHost = o.host
		}
		renderCtx := playbook.RenderContext{
			Host:        renderHost,
			Vars:        playbook.MergedVars(pb.Vars, nil),
			PlaybookDir: playbookDir,
		}
		ops, err := modules.CompileAll(pb, plan, renderCtx)
		if err != nil {
			return fmt.Errorf("compile for %s: %w", hostname, err)
		}
		specs = append(specs, runner.HostSpec{
			Target: runner.Target{
				Hostname:   hostname,
				Addr:       fmt.Sprintf("%s:%d", h.WGIP, o.agentPort),
				ServerName: hostname,
			},
			Ops: ops,
		})
	}

	fmt.Fprintf(out, "applying %d resource op(s) to %d host(s)%s\n",
		countOps(specs), len(specs), checkSuffix(o.check))
	report, err := runner.Run(ctx, runner.Request{
		Hosts:      specs,
		Identity:   id,
		ServerPool: serverPool,
		IsRevoked:  inv.IsRevoked, // CRL-lite: refuse revoked agents
	}, runner.Options{
		Check:       o.check,
		MaxFailures: o.maxFail,
		DialRetries: o.dialRetries,
		Parallelism: o.parallel,
		Timeout:     10 * time.Minute,
	})
	if err != nil {
		return err
	}

	printReport(out, report, o.check, o.verbose)
	return report.Err()
}

func printReport(out io.Writer, report *runner.Report, check bool, verbose bool) {
	// Per-host results in request order.
	for _, res := range report.Results {
		switch {
		case res.Skipped:
			fmt.Fprintf(out, "%-20s SKIPPED (failure policy)\n", res.Hostname)
		case res.Err != nil:
			fmt.Fprintf(out, "%-20s ERROR   %v\n", res.Hostname, res.Err)
		default:
			state := "ok"
			if res.Failed > 0 {
				state = "FAILED"
			} else if res.Changed > 0 {
				state = "changed"
			}
			fmt.Fprintf(out, "%-20s %-8s %d ok, %d changed, %d failed\n",
				res.Hostname, state, res.OK, res.Changed, res.Failed)
			if verbose {
				for _, op := range res.Ops {
					marker := " "
					switch {
					case op.Failed:
						marker = "!"
					case op.Changed:
						marker = "+"
					}
					detail := op.Message
					if detail == "" {
						detail = op.OpType
					}
					fmt.Fprintf(out, "  %s %-10s %s\n", marker, op.OpType, detail)
					if op.Stderr != "" {
						fmt.Fprintf(out, "      stderr: %s\n", strings.TrimSpace(op.Stderr))
					}
				}
			}
		}
	}
	summary := "apply complete"
	if check {
		summary = "check complete (nothing was changed)"
	}
	fmt.Fprintf(out, "%s: %d ok, %d changed, %d failed, %d host(s) failed, %d skipped\n",
		summary, report.OK, report.Changed, report.Failed, report.FailedHosts, report.Skipped)
}

func countOps(specs []runner.HostSpec) int {
	total := 0
	for _, s := range specs {
		total += len(s.Ops)
	}
	return total
}

func checkSuffix(check bool) string {
	if check {
		return " (check mode)"
	}
	return ""
}

// mustAbs returns the absolute path of p (falling back to p on error).
func mustAbs(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return abs
}
