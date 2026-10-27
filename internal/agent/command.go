package agent

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/claymod/claymod/internal/proto"
)

// applyCommand implements the Command op: guard evaluation (onlyIf /
// unlessIf / creates / removes), then execution with captured output.
// The per-op timeout takes precedence over the run-level one.
func (a *Agent) applyCommand(ctx context.Context, op proto.CommandOp, check bool, timeout time.Duration) proto.ApplyResult {
	res := proto.ApplyResult{OpType: proto.OpTypeCommand}
	if op.Timeout > 0 {
		timeout = time.Duration(op.Timeout) * time.Millisecond
	}

	if op.Creates != "" && exists(op.Creates) {
		res.Message = "skipped: " + op.Creates + " exists"
		return res
	}
	if op.Removes != "" && !exists(op.Removes) {
		res.Message = "skipped: " + op.Removes + " absent"
		return res
	}
	if op.OnlyIf != "" {
		ok, err := runGuard(ctx, op.OnlyIf, timeout)
		if err != nil {
			res.Failed = true
			res.Message = "only_if: " + err.Error()
			return res
		}
		if !ok {
			res.Message = "skipped: only_if returned non-zero"
			return res
		}
	}
	if op.UnlessIf != "" {
		ok, err := runGuard(ctx, op.UnlessIf, timeout)
		if err != nil {
			res.Failed = true
			res.Message = "unless_if: " + err.Error()
			return res
		}
		if ok {
			res.Message = "skipped: unless_if returned zero"
			return res
		}
	}

	if check {
		res.Changed = true
		res.Message = "would run " + describe(op)
		return res
	}

	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := buildCommand(cmdCtx, op)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	res.Stdout = clip(stdout.String(), a.maxCapture)
	res.Stderr = clip(stderr.String(), a.maxCapture)
	res.Changed = true

	if err != nil {
		var exitErr *exec.ExitError
		switch {
		case errors.Is(cmdCtx.Err(), context.DeadlineExceeded):
			res.Failed = true
			res.Message = "command timed out"
		case errors.As(err, &exitErr):
			res.Failed = true
			res.Message = "exit " + exitStatus(exitErr)
		default:
			res.Failed = true
			res.Message = "run: " + err.Error()
		}
		return res
	}
	res.Message = "ran " + describe(op)
	return res
}

// exec implements MethodExec (ad-hoc command from `claymod exec`).
// The request's timeout takes precedence over the agent's default.
func (a *Agent) exec(ctx context.Context, params proto.ExecParams) proto.ExecResult {
	timeout := a.opLimit
	if params.Timeout > 0 {
		timeout = time.Duration(params.Timeout) * time.Millisecond
	}
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var cmd *exec.Cmd
	if params.Shell != "" {
		cmd = exec.CommandContext(cmdCtx, "/bin/sh", "-c", params.Shell)
	} else if len(params.Argv) > 0 {
		cmd = exec.CommandContext(cmdCtx, params.Argv[0], params.Argv[1:]...)
	} else {
		return proto.ExecResult{ExitCode: -1, Stderr: "argv or shell is required"}
	}
	if params.Cwd != "" {
		cmd.Dir = params.Cwd
	}
	cmd.Env = os.Environ()
	for k, v := range params.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	res := proto.ExecResult{
		Stdout: clip(stdout.String(), a.maxCapture),
		Stderr: clip(stderr.String(), a.maxCapture),
	}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		res.ExitCode = 0
	case errors.As(err, &exitErr):
		res.ExitCode = exitErr.ExitCode()
	default:
		res.ExitCode = -1
		res.Stderr = clip(res.Stderr+"\n"+err.Error(), a.maxCapture)
	}
	return res
}

// buildCommand constructs the exec.Cmd for one command op.
func buildCommand(ctx context.Context, op proto.CommandOp) *exec.Cmd {
	var cmd *exec.Cmd
	if op.Shell != "" {
		cmd = exec.CommandContext(ctx, "/bin/sh", "-c", op.Shell)
	} else {
		cmd = exec.CommandContext(ctx, op.Argv[0], op.Argv[1:]...)
	}
	if op.Cwd != "" {
		cmd.Dir = op.Cwd
	}
	cmd.Env = os.Environ()
	for k, v := range op.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	return cmd
}

// runGuard evaluates a guard command: success (exit 0) is true. Guards run
// with a bounded timeout and capture nothing.
func runGuard(ctx context.Context, shell string, timeout time.Duration) (bool, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, "/bin/sh", "-c", shell)
	err := cmd.Run()
	if err == nil {
		return true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return false, nil // guard ran and decided "no"
	}
	return false, err // could not run the guard at all
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func describe(op proto.CommandOp) string {
	if op.Shell != "" {
		return "shell " + op.Shell
	}
	return filepath.Base(op.Argv[0])
}

// clip truncates captured output to limit bytes, marking the cut.
func clip(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "\n... (truncated)"
}

// exitStatus renders an ExitError's status.
func exitStatus(err *exec.ExitError) string {
	if status, ok := err.Sys().(syscall.WaitStatus); ok {
		return itoa(status.ExitStatus())
	}
	return err.Error()
}

// itoa avoids importing strconv here for one call.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	k := len(buf)
	for n > 0 {
		k--
		buf[k] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		k--
		buf[k] = '-'
	}
	return string(buf[k:])
}
