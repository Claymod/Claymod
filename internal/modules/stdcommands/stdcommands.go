// Package stdcommands compiles std.commands.* resources into Command ops.
// Script is special: it emits a File op (write the script) followed by a
// Command op (run it).
package stdcommands

import (
	"fmt"

	"github.com/claymod/claymod/internal/modules"
	"github.com/claymod/claymod/internal/playbook"
	"github.com/claymod/claymod/internal/proto"
)

// ShellResource mirrors the std.commands.Shell PKL class.
type ShellResource struct {
	Type     string            `json:"type"`
	Name     string            `json:"name"`
	Command  string            `json:"command"`
	Argv     []string          `json:"argv"`
	Cwd      string            `json:"cwd"`
	Env      map[string]string `json:"env"`
	OnlyIf   string            `json:"onlyIf"`
	UnlessIf string            `json:"unlessIf"`
	Creates  string            `json:"creates"`
	Removes  string            `json:"removes"`
	Timeout  int64             `json:"timeout"`
}

// ScriptResource mirrors the std.commands.Script PKL class.
type ScriptResource struct {
	Type     string            `json:"type"`
	Name     string            `json:"name"`
	Content  string            `json:"content"`
	Path     string            `json:"path"`
	Mode     string            `json:"mode"`
	Cwd      string            `json:"cwd"`
	Env      map[string]string `json:"env"`
	OnlyIf   string            `json:"onlyIf"`
	UnlessIf string            `json:"unlessIf"`
	Timeout  int64             `json:"timeout"`
}

// compileShell emits a single Command op.
func compileShell(res playbook.Resource, ctx playbook.RenderContext) ([]proto.Op, error) {
	var r ShellResource
	if err := modules.DecodeResource(res, &r); err != nil {
		return nil, err
	}
	hasShell := r.Command != ""
	hasArgv := len(r.Argv) > 0
	if hasShell == hasArgv {
		return nil, fmt.Errorf("exactly one of command or argv must be set")
	}
	op := &proto.CommandOp{
		Cwd:      r.Cwd,
		Env:      r.Env,
		OnlyIf:   r.OnlyIf,
		UnlessIf: r.UnlessIf,
		Creates:  r.Creates,
		Removes:  r.Removes,
		Timeout:  r.Timeout,
	}
	if hasShell {
		op.Shell = r.Command
	} else {
		op.Argv = r.Argv
	}
	return []proto.Op{{OpType: proto.OpTypeCommand, Command: op}}, nil
}

// compileScript renders the script server-side and emits two ops: write
// the script file, then run it.
func compileScript(res playbook.Resource, ctx playbook.RenderContext) ([]proto.Op, error) {
	var r ScriptResource
	if err := modules.DecodeResource(res, &r); err != nil {
		return nil, err
	}
	if r.Path == "" {
		return nil, fmt.Errorf("path is required")
	}
	if err := playbook.ValidatePath(r.Path); err != nil {
		return nil, err
	}
	mode := r.Mode
	if mode == "" {
		mode = "0755"
	}
	// The script content is rendered server-side with the host's vars.
	renderCtx := playbook.RenderContext{
		Host:        ctx.Host,
		Vars:        ctx.Vars,
		PlaybookDir: ctx.PlaybookDir,
	}
	content, err := playbook.RenderTemplateString(r.Content, renderCtx)
	if err != nil {
		return nil, err
	}
	return []proto.Op{
		{
			OpType: proto.OpTypeFile,
			File: &proto.FileOp{
				Path:    r.Path,
				Content: content,
				Mode:    mode,
				Ensure:  proto.EnsureFile,
			},
		},
		{
			OpType: proto.OpTypeCommand,
			Command: &proto.CommandOp{
				Argv:     []string{r.Path},
				Cwd:      r.Cwd,
				Env:      r.Env,
				OnlyIf:   r.OnlyIf,
				UnlessIf: r.UnlessIf,
				Timeout:  r.Timeout,
			},
		},
	}, nil
}

// init registers the std.commands compilers.
func init() {
	modules.Register("std.commands.Shell", modules.CompilerFunc(compileShell))
	modules.Register("std.commands.Script", modules.CompilerFunc(compileScript))
}
