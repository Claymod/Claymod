// Package stdfiles compiles std.files.* resources into File ops.
// File contents are rendered server-side (templates included) so the
// agent stays dumb.
package stdfiles

import (
	"fmt"
	"os"

	"github.com/claymod/claymod/internal/modules"
	"github.com/claymod/claymod/internal/playbook"
	"github.com/claymod/claymod/internal/proto"
)

// CopyResource mirrors the std.files.Copy PKL class.
type CopyResource struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	Source string `json:"source"`
	Dest   string `json:"dest"`
	Mode   string `json:"mode"`
	Owner  string `json:"owner"`
	Group  string `json:"group"`
	Backup bool   `json:"backup"`
}

// TemplateResource mirrors the std.files.Template PKL class.
type TemplateResource struct {
	Type   string            `json:"type"`
	Name   string            `json:"name"`
	Source string            `json:"source"`
	Dest   string            `json:"dest"`
	Mode   string            `json:"mode"`
	Vars   map[string]string `json:"vars"`
	Owner  string            `json:"owner"`
	Group  string            `json:"group"`
	Backup bool              `json:"backup"`
}

// DirectoryResource mirrors the std.files.Directory PKL class.
type DirectoryResource struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	Path   string `json:"path"`
	Mode   string `json:"mode"`
	Ensure string `json:"ensure"`
	Owner  string `json:"owner"`
	Group  string `json:"group"`
}

// compileCopy reads the source file server-side and emits a File op.
func compileCopy(res playbook.Resource, ctx playbook.RenderContext) ([]proto.Op, error) {
	var r CopyResource
	if err := modules.DecodeResource(res, &r); err != nil {
		return nil, err
	}
	if r.Source == "" {
		return nil, fmt.Errorf("source is required")
	}
	if r.Dest == "" {
		return nil, fmt.Errorf("dest is required")
	}
	if err := playbook.ValidatePath(r.Dest); err != nil {
		return nil, err
	}
	source := playbook.ResolveSource(ctx.PlaybookDir, r.Source)
	content, err := os.ReadFile(source)
	if err != nil {
		return nil, fmt.Errorf("read source %s: %w", r.Source, err)
	}
	return []proto.Op{{
		OpType: proto.OpTypeFile,
		File: &proto.FileOp{
			Path:    r.Dest,
			Content: string(content),
			Mode:    r.Mode,
			Owner:   r.Owner,
			Group:   r.Group,
			Ensure:  proto.EnsureFile,
			Backup:  r.Backup,
		},
	}}, nil
}

// compileTemplate renders the template server-side and emits a File op.
func compileTemplate(res playbook.Resource, ctx playbook.RenderContext) ([]proto.Op, error) {
	var r TemplateResource
	if err := modules.DecodeResource(res, &r); err != nil {
		return nil, err
	}
	if r.Source == "" {
		return nil, fmt.Errorf("source is required")
	}
	if r.Dest == "" {
		return nil, fmt.Errorf("dest is required")
	}
	if err := playbook.ValidatePath(r.Dest); err != nil {
		return nil, err
	}
	source := playbook.ResolveSource(ctx.PlaybookDir, r.Source)
	renderCtx := playbook.RenderContext{
		Host:        ctx.Host,
		Vars:        playbook.MergedVars(ctx.Vars, r.Vars),
		PlaybookDir: ctx.PlaybookDir,
	}
	content, err := playbook.RenderTemplate(source, renderCtx)
	if err != nil {
		return nil, err
	}
	return []proto.Op{{
		OpType: proto.OpTypeFile,
		File: &proto.FileOp{
			Path:    r.Dest,
			Content: content,
			Mode:    r.Mode,
			Owner:   r.Owner,
			Group:   r.Group,
			Ensure:  proto.EnsureFile,
			Backup:  r.Backup,
		},
	}}, nil
}

// compileDirectory emits a File op with ensure=directory (or absent).
func compileDirectory(res playbook.Resource, ctx playbook.RenderContext) ([]proto.Op, error) {
	var r DirectoryResource
	if err := modules.DecodeResource(res, &r); err != nil {
		return nil, err
	}
	if r.Path == "" {
		return nil, fmt.Errorf("path is required")
	}
	if err := playbook.ValidatePath(r.Path); err != nil {
		return nil, err
	}
	ensure := r.Ensure
	if ensure == "" {
		ensure = proto.EnsureDirectory
	}
	switch ensure {
	case proto.EnsureDirectory, proto.EnsureAbsent:
	default:
		return nil, fmt.Errorf("invalid ensure %q (want %s or %s)",
			ensure, proto.EnsureDirectory, proto.EnsureAbsent)
	}
	return []proto.Op{{
		OpType: proto.OpTypeFile,
		File: &proto.FileOp{
			Path:   r.Path,
			Mode:   r.Mode,
			Owner:  r.Owner,
			Group:  r.Group,
			Ensure: ensure,
		},
	}}, nil
}

// init registers the std.files compilers.
func init() {
	modules.Register("std.files.Copy", modules.CompilerFunc(compileCopy))
	modules.Register("std.files.Template", modules.CompilerFunc(compileTemplate))
	modules.Register("std.files.Directory", modules.CompilerFunc(compileDirectory))
}
