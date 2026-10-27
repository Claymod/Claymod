// Package pkl wraps the pkl CLI (a server-side dependency) used to
// evaluate PKL playbooks to JSON. Agents never run PKL: playbooks compile
// to primitive ops on the control server only.
//
// The pkl binary is expected on PATH (install it with
// scripts/bootstrap-pkl.sh); when it is missing every call fails with
// ErrPklNotFound so callers can point operators at the bootstrap script.
package pkl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// ErrPklNotFound is returned when the pkl binary cannot be found.
var ErrPklNotFound = errors.New("pkl: pkl CLI not found on PATH (server-side dependency — install it with scripts/bootstrap-pkl.sh)")

// DefaultTimeout bounds one evaluation.
const DefaultTimeout = 60 * time.Second

// EvalOptions configures one evaluation.
type EvalOptions struct {
	// ModulePath directories are searched for modulepath: URIs
	// (e.g. the shipped pkl/ schema directory).
	ModulePath []string
	// Properties are external properties passed as -p name=value (argv,
	// never process-environment mutation). Playbooks read them with
	// read?("prop:<name>").
	Properties map[string]string
	// Env are environment variables passed to the pkl child as
	// -e name=value. Playbooks read them with read?("env:<name>").
	Env map[string]string
	// Timeout bounds the evaluation (default DefaultTimeout).
	Timeout time.Duration
}

// Evaluator runs the pkl CLI.
type Evaluator struct {
	// PklBinary defaults to "pkl" on PATH (overridable in tests).
	PklBinary string
}

// New returns an Evaluator using the pkl binary on PATH.
func New() *Evaluator {
	return &Evaluator{PklBinary: "pkl"}
}

// Available reports whether the pkl CLI is installed.
func (e *Evaluator) Available() bool {
	_, err := exec.LookPath(e.bin())
	return err == nil
}

// Version returns the pkl CLI version string ("Pkl x.y.z ...").
func (e *Evaluator) Version() (string, error) {
	out, err := exec.Command(e.bin(), "--version").Output()
	if err != nil {
		return "", e.wrapErr(err, "")
	}
	return strings.TrimSpace(string(out)), nil
}

// Evaluate runs `pkl eval --format json` on the given module and returns
// the raw JSON document. Evaluation errors carry pkl's own diagnostics.
func (e *Evaluator) Evaluate(ctx context.Context, module string, opts EvalOptions) (json.RawMessage, error) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := []string{"eval", "--format", "json", "--color", "never"}
	if len(opts.ModulePath) > 0 {
		args = append(args, "--module-path", strings.Join(opts.ModulePath, ":"))
	}
	for _, k := range sortedKeys(opts.Properties) {
		args = append(args, "-p", k+"="+opts.Properties[k])
	}
	for _, k := range sortedKeys(opts.Env) {
		args = append(args, "-e", k+"="+opts.Env[k])
	}
	args = append(args, module)

	cmd := exec.CommandContext(ctx, e.bin(), args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("pkl: evaluation of %s timed out after %s", module, timeout)
		}
		if errors.Is(err, exec.ErrNotFound) || isNotFound(err) {
			return nil, ErrPklNotFound
		}
		return nil, e.wrapErr(err, stderr.String())
	}
	var raw json.RawMessage
	if err := json.Unmarshal(stdout.Bytes(), &raw); err != nil {
		return nil, fmt.Errorf("pkl: output of %s is not valid JSON: %w", module, err)
	}
	return raw, nil
}

// EvaluateTo evaluates the module and unmarshals the JSON into target.
func (e *Evaluator) EvaluateTo(ctx context.Context, module string, opts EvalOptions, target any) error {
	raw, err := e.Evaluate(ctx, module, opts)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return fmt.Errorf("pkl: decode %s: %w", module, err)
	}
	return nil
}

func (e *Evaluator) bin() string {
	if e.PklBinary != "" {
		return e.PklBinary
	}
	return "pkl"
}

// wrapErr turns an exec failure into an error carrying pkl's stderr
// diagnostics (which are usually excellent) and the missing-binary hint.
func (e *Evaluator) wrapErr(err error, stderr string) error {
	if isNotFound(err) {
		return ErrPklNotFound
	}
	msg := strings.TrimSpace(stderr)
	if msg == "" {
		msg = err.Error()
	}
	return fmt.Errorf("pkl: %s", msg)
}

func isNotFound(err error) bool {
	return errors.Is(err, exec.ErrNotFound) || strings.Contains(err.Error(), "executable file not found")
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
