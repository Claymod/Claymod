// Package stdsysctl compiles std.sysctl.* resources into Command ops.
// Runtime-only by design: the recipe reads with `sysctl -n` and writes
// with `sysctl key=value` — the form every implementation (procps,
// busybox, BSD) accepts as a write (verified 2026-10-30 on macOS,
// alpine and debian). Persistence is an explicit std.files resource.
package stdsysctl

import (
	"fmt"
	"strings"

	"github.com/claymod/claymod/internal/modules"
	"github.com/claymod/claymod/internal/modules/shell"
	"github.com/claymod/claymod/internal/playbook"
	"github.com/claymod/claymod/internal/proto"
)

// SysctlResource mirrors the std.sysctl.Sysctl PKL class.
type SysctlResource struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Key   string `json:"key"`
	Value string `json:"value"`
}

// compileSysctl emits a guarded Command op: skipped while
// `sysctl -n key` already reports the wanted value.
func compileSysctl(res playbook.Resource, ctx playbook.RenderContext) ([]proto.Op, error) {
	var r SysctlResource
	if err := modules.DecodeResource(res, &r); err != nil {
		return nil, err
	}
	if r.Key == "" {
		return nil, fmt.Errorf("key is required")
	}
	if strings.ContainsAny(r.Key, " \t\n") {
		return nil, fmt.Errorf("key must be a single sysctl name without whitespace: %q", r.Key)
	}
	if r.Value == "" {
		return nil, fmt.Errorf("value is required")
	}
	if strings.Contains(r.Value, "\n") {
		return nil, fmt.Errorf("value must be a single line")
	}
	qKey, qValue := shell.Quote(r.Key), shell.Quote(r.Value)
	op := &proto.CommandOp{
		// Already at the wanted value: nothing to do (2>/dev/null keeps
		// an unknown key's error quiet; the write then fails visibly).
		UnlessIf: fmt.Sprintf(`[ "$(sysctl -n %s 2>/dev/null)" = %s ]`, qKey, qValue),
		// `sysctl key=value` is a write on procps, busybox and BSD alike.
		Shell: fmt.Sprintf("sysctl %s=%s", qKey, qValue),
	}
	return []proto.Op{{OpType: proto.OpTypeCommand, Command: op}}, nil
}

// init registers the std.sysctl compiler.
func init() {
	modules.Register("std.sysctl.Sysctl", modules.CompilerFunc(compileSysctl))
}
