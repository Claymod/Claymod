package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/claymod/claymod/internal/config"
	"github.com/claymod/claymod/internal/inventory"
	"github.com/claymod/claymod/internal/proto"
	"github.com/claymod/claymod/internal/state"
)

// ExitCoder is an error carrying a process exit code (used by `exec` to
// propagate the remote command's exit status).
type ExitCoder interface {
	error
	ExitCode() int
}

// exitCodeError implements ExitCoder.
type exitCodeError struct {
	code int
	msg  string
}

func (e *exitCodeError) Error() string { return e.msg }
func (e *exitCodeError) ExitCode() int { return e.code }

func newExecCmd() *cobra.Command {
	var (
		dataDir       string
		inventoryPath string
		agentPort     int
		shell         string
		cwd           string
		timeout       time.Duration
	)
	cmd := &cobra.Command{
		Use:   "exec [flags] -- <command> [args...]",
		Short: "Run an ad-hoc command on a host",
		Long: `Exec runs a single command on one enrolled host over the framed
mTLS protocol (the same Apply channel) and prints its output. The
command runs with the agent's privileges. The process exit code mirrors
the remote command's exit code.`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			hostname := cmd.Flags().Lookup("host").Value.String()
			if hostname == "" {
				return fmt.Errorf("--host is required")
			}
			if shell == "" && len(args) == 0 {
				return fmt.Errorf("give a command after -- , or use --shell")
			}
			if shell != "" && len(args) > 0 {
				return fmt.Errorf("--shell and a -- <command> are mutually exclusive")
			}
			return runExec(cmd.Context(), cmd, execOptions{
				hostname:      hostname,
				dataDir:       dataDir,
				inventoryPath: inventoryPath,
				agentPort:     agentPort,
				shell:         shell,
				argv:          args,
				cwd:           cwd,
				timeout:       timeout,
			})
		},
	}
	cmd.Flags().String("host", "", "target host (hostname from the inventory)")
	cmd.Flags().StringVar(&dataDir, "data-dir", "claymod-data", "server data directory (control identity)")
	cmd.Flags().StringVar(&inventoryPath, "inventory", "", "inventory database (default: <data-dir>/inventory.db)")
	cmd.Flags().IntVar(&agentPort, "agent-port", 2323, "agent port on the WireGuard overlay")
	cmd.Flags().StringVar(&shell, "shell", "", "shell command line (run with /bin/sh -c on the host)")
	cmd.Flags().StringVar(&cwd, "cwd", "", "working directory on the host")
	cmd.Flags().DurationVar(&timeout, "timeout", 2*time.Minute, "command timeout")
	return cmd
}

type execOptions struct {
	hostname      string
	dataDir       string
	inventoryPath string
	agentPort     int
	shell         string
	argv          []string
	cwd           string
	timeout       time.Duration
}

func runExec(ctx context.Context, cmd *cobra.Command, o execOptions) error {
	out := cmd.OutOrStdout()
	ctrl, err := state.LoadControlIdentity(o.dataDir)
	if err != nil {
		return err
	}
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

	host, err := inv.GetHost(o.hostname)
	if err != nil {
		return fmt.Errorf("resolve host %s: %w", o.hostname, err)
	}

	conn, err := proto.Dial(fmt.Sprintf("%s:%d", host.WGIP, o.agentPort), o.hostname, ctrl.Identity, ctrl.ServerPool)
	if err != nil {
		return err
	}
	defer conn.Close()

	params := proto.ExecParams{
		Shell:   o.shell,
		Argv:    o.argv,
		Cwd:     o.cwd,
		Timeout: o.timeout.Milliseconds(),
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return err
	}
	if err := conn.Send(proto.Request{ID: "exec-1", Method: proto.MethodExec, Params: raw}); err != nil {
		return err
	}
	var resp proto.Response
	if err := conn.Recv(&resp); err != nil {
		return err
	}
	if resp.Error != nil {
		return resp.Error
	}
	var res proto.ExecResult
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		return err
	}
	writeStream(out, res.Stdout, res.Stderr)
	if res.ExitCode != 0 {
		return &exitCodeError{
			code: res.ExitCode,
			msg:  fmt.Sprintf("remote command on %s exited %d", o.hostname, res.ExitCode),
		}
	}
	return nil
}

// writeStream writes captured stdout/stderr to out.
func writeStream(out io.Writer, stdout, stderr string) {
	if stdout != "" {
		fmt.Fprint(out, stdout)
		if stdout[len(stdout)-1] != '\n' {
			fmt.Fprintln(out)
		}
	}
	if stderr != "" {
		fmt.Fprint(out, stderr)
		if stderr[len(stderr)-1] != '\n' {
			fmt.Fprintln(out)
		}
	}
}
