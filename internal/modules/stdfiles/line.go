package stdfiles

import (
	"fmt"
	"strings"

	"github.com/claymod/claymod/internal/modules"
	"github.com/claymod/claymod/internal/modules/shell"
	"github.com/claymod/claymod/internal/playbook"
	"github.com/claymod/claymod/internal/proto"
)

// LineResource mirrors the std.files.Line PKL class.
type LineResource struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	Path   string `json:"path"`
	Line   string `json:"line"`
	Ensure string `json:"ensure"`
}

// SymlinkResource mirrors the std.files.Symlink PKL class.
type SymlinkResource struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	Path   string `json:"path"`
	Target string `json:"target"`
	Force  bool   `json:"force"`
}

// shellQuote single-quotes s for POSIX sh (see the shell package); a
// local alias keeps the recipes below readable.
func shellQuote(s string) string { return shell.Quote(s) }

// compileLine emits a guarded Command op that appends the line (present)
// or rewrites the file without it (absent). Both recipes are idempotent:
// the guard skips the run once the file is already in the wanted state,
// and the absent recipe writes through `cat >` so the file keeps its
// inode, mode and owner.
func compileLine(res playbook.Resource, ctx playbook.RenderContext) ([]proto.Op, error) {
	var r LineResource
	if err := modules.DecodeResource(res, &r); err != nil {
		return nil, err
	}
	if r.Path == "" {
		return nil, fmt.Errorf("path is required")
	}
	if err := playbook.ValidatePath(r.Path); err != nil {
		return nil, err
	}
	if strings.Contains(r.Line, "\n") {
		return nil, fmt.Errorf("line must be a single line (contains a newline)")
	}
	ensure := r.Ensure
	if ensure == "" {
		ensure = "present"
	}
	qLine, qPath := shellQuote(r.Line), shellQuote(r.Path)
	op := &proto.CommandOp{}
	switch ensure {
	case "present":
		// Skip when the exact line is already there.
		op.UnlessIf = fmt.Sprintf("grep -qxF -- %s %s", qLine, qPath)
		// First give a non-empty file a trailing newline if it lacks one
		// (tail -c 1 of a file ending in \n command-substitutes to empty;
		// 2>/dev/null keeps a missing file quiet), then append — otherwise
		// the managed line glues onto the last line.
		op.Shell = fmt.Sprintf(`[ -z "$(tail -c 1 %s 2>/dev/null)" ] || printf '\n' >> %s
printf '%%s\n' %s >> %s`, qPath, qPath, qLine, qPath)
	case "absent":
		// Skip when the line is gone (also skips a missing file: grep
		// exits 2 on a missing path).
		op.OnlyIf = fmt.Sprintf("grep -qxF -- %s %s", qLine, qPath)
		op.Shell = fmt.Sprintf(`tmp=$(mktemp) || exit 1
trap 'rm -f "$tmp"' EXIT
grep -vxF -- %s %s > "$tmp"; s=$?; [ "$s" -eq 0 ] || [ "$s" -eq 1 ] || exit "$s"
cat "$tmp" > %s`, qLine, qPath, qPath)
	default:
		return nil, fmt.Errorf(`invalid ensure %q (want "present" or "absent")`, ensure)
	}
	return []proto.Op{{OpType: proto.OpTypeCommand, Command: op}}, nil
}

// compileSymlink emits a guarded Command op that points path at target.
// Without force, a non-symlink occupying the path fails the op loudly
// instead of being clobbered; a wrong-target symlink is always relinked.
func compileSymlink(res playbook.Resource, ctx playbook.RenderContext) ([]proto.Op, error) {
	var r SymlinkResource
	if err := modules.DecodeResource(res, &r); err != nil {
		return nil, err
	}
	if r.Path == "" {
		return nil, fmt.Errorf("path is required")
	}
	if err := playbook.ValidatePath(r.Path); err != nil {
		return nil, err
	}
	if r.Target == "" {
		return nil, fmt.Errorf("target is required")
	}
	qPath, qTarget := shellQuote(r.Path), shellQuote(r.Target)
	op := &proto.CommandOp{
		// Already pointing at the target: nothing to do.
		UnlessIf: fmt.Sprintf(`[ "$(readlink %s)" = %s ]`, qPath, qTarget),
	}
	link := fmt.Sprintf("rm -f %s && ln -s %s %s", qPath, qTarget, qPath)
	if r.Force {
		op.Shell = link
	} else {
		// The path is a printf ARGUMENT (single-quoted), never part of a
		// double-quoted message: a path with `"` or `$(...)` must not be
		// able to garble or execute inside the refusal branch.
		op.Shell = fmt.Sprintf(`if [ -e %s ] && ! [ -L %s ]; then printf '%%s exists and is not a symlink (set force = true to replace)\n' %s >&2; exit 1; fi
%s`, qPath, qPath, qPath, link)
	}
	return []proto.Op{{OpType: proto.OpTypeCommand, Command: op}}, nil
}

// init registers the std.files.Line and std.files.Symlink compilers.
func init() {
	modules.Register("std.files.Line", modules.CompilerFunc(compileLine))
	modules.Register("std.files.Symlink", modules.CompilerFunc(compileSymlink))
}
