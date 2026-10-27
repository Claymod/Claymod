package agent

import (
	"context"
	"errors"
	"os/exec"
	"strings"

	"github.com/claymod/claymod/internal/proto"
)

// ServiceRunner executes service operations. The agent talks to it instead
// of calling systemctl directly, so tests can substitute a fake.
type ServiceRunner interface {
	// IsEnabled reports whether a unit is enabled at boot.
	IsEnabled(ctx context.Context, unit string) (bool, error)
	// State reports the unit's active state ("active", "inactive", ...).
	State(ctx context.Context, unit string) (string, error)
	// Enable enables the unit at boot.
	Enable(ctx context.Context, unit string) error
	// Disable disables the unit at boot.
	Disable(ctx context.Context, unit string) error
	// Start starts the unit.
	Start(ctx context.Context, unit string) error
	// Stop stops the unit.
	Stop(ctx context.Context, unit string) error
	// Restart restarts the unit.
	Restart(ctx context.Context, unit string) error
	// Reload reloads the unit (falls back to restart when unsupported).
	Reload(ctx context.Context, unit string) error
}

// SystemctlRunner drives systemd through the systemctl binary.
type SystemctlRunner struct{}

func (SystemctlRunner) IsEnabled(ctx context.Context, unit string) (bool, error) {
	out, err := exec.CommandContext(ctx, "systemctl", "is-enabled", unit).CombinedOutput()
	status := strings.TrimSpace(string(out))
	// systemctl is-enabled exits non-zero for "disabled"/"static" — that
	// is an answer, not an error.
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return status == "enabled" || status == "static" || status == "indirect", nil
		}
		return false, err
	}
	return status == "enabled" || status == "static" || status == "indirect", nil
}

func (SystemctlRunner) State(ctx context.Context, unit string) (string, error) {
	out, err := exec.CommandContext(ctx, "systemctl", "is-active", unit).CombinedOutput()
	status := strings.TrimSpace(string(out))
	if status == "" {
		status = "unknown"
	}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return status, nil // "inactive"/"failed" is an answer
		}
		return "", err
	}
	return status, nil
}

func (SystemctlRunner) Enable(ctx context.Context, unit string) error {
	return runSystemctl(ctx, "enable", unit)
}

func (SystemctlRunner) Disable(ctx context.Context, unit string) error {
	return runSystemctl(ctx, "disable", unit)
}

func (SystemctlRunner) Start(ctx context.Context, unit string) error {
	return runSystemctl(ctx, "start", unit)
}

func (SystemctlRunner) Stop(ctx context.Context, unit string) error {
	return runSystemctl(ctx, "stop", unit)
}

func (SystemctlRunner) Restart(ctx context.Context, unit string) error {
	return runSystemctl(ctx, "restart", unit)
}

func (SystemctlRunner) Reload(ctx context.Context, unit string) error {
	err := runSystemctl(ctx, "reload", unit)
	if err == nil {
		return nil
	}
	// Units without an ExecReload are restarted instead.
	if strings.Contains(err.Error(), "reload") {
		return runSystemctl(ctx, "restart", unit)
	}
	return err
}

func runSystemctl(ctx context.Context, verb, unit string) error {
	out, err := exec.CommandContext(ctx, "systemctl", verb, unit).CombinedOutput()
	if err != nil {
		return errors.New(strings.TrimSpace(string(out)) + ": " + err.Error())
	}
	return nil
}

// applyService implements the Service op.
func (a *Agent) applyService(ctx context.Context, op proto.ServiceOp, check bool) proto.ApplyResult {
	res := proto.ApplyResult{OpType: proto.OpTypeService}
	if op.Unit == "" {
		res.Failed = true
		res.Message = "service unit is required"
		return res
	}
	switch op.State {
	case "", proto.StateStarted, proto.StateStopped, proto.StateRestarted, proto.StateReloaded:
	default:
		res.Failed = true
		res.Message = "invalid state " + op.State
		return res
	}

	// Enabled state first.
	if op.Enabled != nil {
		current, err := a.svc.IsEnabled(ctx, op.Unit)
		if err != nil {
			res.Failed = true
			res.Message = "is-enabled: " + err.Error()
			return res
		}
		if current != *op.Enabled {
			if check {
				res.Changed = true
				res.Message = "would toggle enabled state"
			} else if *op.Enabled {
				if err := a.svc.Enable(ctx, op.Unit); err != nil {
					res.Failed = true
					res.Message = "enable: " + err.Error()
					return res
				}
				res.Changed = true
			} else {
				if err := a.svc.Disable(ctx, op.Unit); err != nil {
					res.Failed = true
					res.Message = "disable: " + err.Error()
					return res
				}
				res.Changed = true
			}
		}
	}

	// Running state.
	switch op.State {
	case "":
		if res.Message == "" {
			res.Message = "already in desired state"
		}
		return res
	case proto.StateStarted:
		state, err := a.svc.State(ctx, op.Unit)
		if err != nil {
			res.Failed = true
			res.Message = "is-active: " + err.Error()
			return res
		}
		if state == "active" {
			if res.Message == "" {
				res.Message = "already active"
			}
			return res
		}
		if check {
			res.Changed = true
			res.Message = "would start " + op.Unit
			return res
		}
		if err := a.svc.Start(ctx, op.Unit); err != nil {
			res.Failed = true
			res.Message = "start: " + err.Error()
			return res
		}
		res.Changed = true
		res.Message = "started " + op.Unit
		return res
	case proto.StateStopped:
		state, err := a.svc.State(ctx, op.Unit)
		if err != nil {
			res.Failed = true
			res.Message = "is-active: " + err.Error()
			return res
		}
		if state == "inactive" || state == "failed" {
			if res.Message == "" {
				res.Message = "already stopped"
			}
			return res
		}
		if check {
			res.Changed = true
			res.Message = "would stop " + op.Unit
			return res
		}
		if err := a.svc.Stop(ctx, op.Unit); err != nil {
			res.Failed = true
			res.Message = "stop: " + err.Error()
			return res
		}
		res.Changed = true
		res.Message = "stopped " + op.Unit
		return res
	case proto.StateRestarted:
		if check {
			res.Changed = true
			res.Message = "would restart " + op.Unit
			return res
		}
		if err := a.svc.Restart(ctx, op.Unit); err != nil {
			res.Failed = true
			res.Message = "restart: " + err.Error()
			return res
		}
		res.Changed = true
		res.Message = "restarted " + op.Unit
		return res
	case proto.StateReloaded:
		if check {
			res.Changed = true
			res.Message = "would reload " + op.Unit
			return res
		}
		if err := a.svc.Reload(ctx, op.Unit); err != nil {
			res.Failed = true
			res.Message = "reload: " + err.Error()
			return res
		}
		res.Changed = true
		res.Message = "reloaded " + op.Unit
		return res
	}
	return res
}
