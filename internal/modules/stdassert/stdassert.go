// Package stdassert compiles std.assert.* resources into Command ops
// with assertion semantics: a non-zero exit fails the apply for the
// host (the agent already treats a failed command op that way), so
// assertions are ordinary operations — agents need nothing new.
package stdassert

import (
	"fmt"
	"strings"

	"github.com/claymod/claymod/internal/modules"
	"github.com/claymod/claymod/internal/modules/shell"
	"github.com/claymod/claymod/internal/playbook"
	"github.com/claymod/claymod/internal/proto"
)

// CommandResource mirrors the std.assert.Command PKL class.
type CommandResource struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Command string `json:"command"`
	Timeout int64  `json:"timeout"`
}

// FileContainsResource mirrors the std.assert.FileContains PKL class.
type FileContainsResource struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Path    string `json:"path"`
	Pattern string `json:"pattern"`
}

// PortListeningResource mirrors the std.assert.PortListening PKL class.
type PortListeningResource struct {
	Type string `json:"type"`
	Name string `json:"name"`
	Port int    `json:"port"`
}

// compileCommand asserts that command exits 0.
func compileCommand(res playbook.Resource, ctx playbook.RenderContext) ([]proto.Op, error) {
	var r CommandResource
	if err := modules.DecodeResource(res, &r); err != nil {
		return nil, err
	}
	if strings.TrimSpace(r.Command) == "" {
		return nil, fmt.Errorf("command is required")
	}
	return []proto.Op{{
		OpType: proto.OpTypeCommand,
		Command: &proto.CommandOp{
			Shell:   r.Command,
			Timeout: r.Timeout,
		},
	}}, nil
}

// compileFileContains asserts that path contains the fixed pattern
// (grep -F — literal, no regex surprises). A missing file fails.
func compileFileContains(res playbook.Resource, ctx playbook.RenderContext) ([]proto.Op, error) {
	var r FileContainsResource
	if err := modules.DecodeResource(res, &r); err != nil {
		return nil, err
	}
	if r.Path == "" {
		return nil, fmt.Errorf("path is required")
	}
	if err := playbook.ValidatePath(r.Path); err != nil {
		return nil, err
	}
	if r.Pattern == "" {
		return nil, fmt.Errorf("pattern is required")
	}
	if strings.Contains(r.Pattern, "\n") {
		return nil, fmt.Errorf("pattern must be a single line")
	}
	return []proto.Op{{
		OpType: proto.OpTypeCommand,
		Command: &proto.CommandOp{
			Shell: fmt.Sprintf("grep -qF -- %s %s", shell.Quote(r.Pattern), shell.Quote(r.Path)),
		},
	}}, nil
}

// compilePortListening asserts that something LISTENS on the TCP port.
// ss first (systemd distros), netstat fallback (busybox and BSD): both
// match the port as a whole address component ("[:.]PORT( |$)") so
// :8080 never satisfies :80.
func compilePortListening(res playbook.Resource, ctx playbook.RenderContext) ([]proto.Op, error) {
	var r PortListeningResource
	if err := modules.DecodeResource(res, &r); err != nil {
		return nil, err
	}
	if r.Port < 1 || r.Port > 65535 {
		return nil, fmt.Errorf("port must be in 1..65535, got %d", r.Port)
	}
	shellText := fmt.Sprintf(`if command -v ss >/dev/null 2>&1; then
  ss -ltn 2>/dev/null | awk -v p='%d' '$1 == "LISTEN" && $0 ~ "[:.]"p"( |$)"' | grep -q .
elif command -v netstat >/dev/null 2>&1; then
  netstat -an 2>/dev/null | awk -v p='%d' 'tolower($0) ~ /listen/ && $0 ~ "[:.]"p"( |$)"' | grep -q .
else
  echo "std.assert: need ss or netstat to check port %d" >&2
  exit 1
fi`, r.Port, r.Port, r.Port)
	return []proto.Op{{
		OpType:  proto.OpTypeCommand,
		Command: &proto.CommandOp{Shell: shellText},
	}}, nil
}

// init registers the std.assert compilers.
func init() {
	modules.Register("std.assert.Command", modules.CompilerFunc(compileCommand))
	modules.Register("std.assert.FileContains", modules.CompilerFunc(compileFileContains))
	modules.Register("std.assert.PortListening", modules.CompilerFunc(compilePortListening))
}
