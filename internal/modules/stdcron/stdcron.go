// Package stdcron compiles std.cron.* resources into Command ops that
// manage entries in the invoking user's crontab via crontab(1).
//
// Entries carry a trailing `# claymod:<name>` marker comment: it makes
// install, update and removal exact (grep on the marker) and idempotent
// (the guard matches the whole entry line). Trailing comments are safe
// because cron hands the command to sh — the marker is a dead comment.
package stdcron

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/claymod/claymod/internal/modules"
	"github.com/claymod/claymod/internal/modules/shell"
	"github.com/claymod/claymod/internal/playbook"
	"github.com/claymod/claymod/internal/proto"
)

// EntryResource mirrors the std.cron.Entry PKL class.
type EntryResource struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Schedule string `json:"schedule"`
	Command  string `json:"command"`
	Ensure   string `json:"ensure"`
}

// validateName rejects names that could break the single-line marker or
// the crontab entry (the marker is `# claymod:<name>`).
func validateName(name string) error {
	if strings.ContainsAny(name, "\n\r#") {
		return fmt.Errorf("resource name must not contain newlines or # (marker: # claymod:<name>)")
	}
	return nil
}

// singleLine validates a field that must not break the entry line.
func singleLine(field, v string) error {
	if v == "" {
		return fmt.Errorf("%s is required", field)
	}
	if strings.Contains(v, "\n") {
		return fmt.Errorf("%s must be a single line", field)
	}
	return nil
}

// compileEntry emits a guarded Command op installing (present) or
// removing (absent) the marked crontab line.
func compileEntry(res playbook.Resource, ctx playbook.RenderContext) ([]proto.Op, error) {
	var r EntryResource
	if err := modules.DecodeResource(res, &r); err != nil {
		return nil, err
	}
	if err := validateName(r.Name); err != nil {
		return nil, err
	}
	if err := singleLine("schedule", r.Schedule); err != nil {
		return nil, err
	}
	if err := singleLine("command", r.Command); err != nil {
		return nil, err
	}
	ensure := r.Ensure
	if ensure == "" {
		ensure = "present"
	}

	qName, qSched, qCmd := shell.Quote(r.Name), shell.Quote(r.Schedule), shell.Quote(r.Command)
	entry := fmt.Sprintf("%s %s # claymod:%s", r.Schedule, r.Command, r.Name)
	qEntry := shell.Quote(entry)
	// The marker regex is end-anchored ($): a resource named "backup"
	// must never match another resource's "# claymod:backup-daily" line.
	// QuoteMeta keeps regex metacharacters in the name literal; the
	// pattern travels as a single-quoted shell word, so any name is safe.
	marker := "# claymod:" + r.Name
	qMarker := shell.Quote(regexp.QuoteMeta(marker) + "$")
	// Read the current crontab (missing crontab = empty), dropping every
	// line carrying this resource's marker.
	rewrite := fmt.Sprintf(`tmp=$(mktemp) || exit 1
trap 'rm -f "$tmp"' EXIT
crontab -l 2>/dev/null | grep -vE -- %s > "$tmp" || true
`, qMarker)

	op := &proto.CommandOp{}
	switch ensure {
	case "present":
		// Skip when the exact marked entry is already installed.
		op.UnlessIf = fmt.Sprintf("crontab -l 2>/dev/null | grep -qFx -- %s", qEntry)
		op.Shell = rewrite + fmt.Sprintf(`{ cat "$tmp"; printf '%%s %%s # claymod:%%s\n' %s %s %s; } | crontab -
`, qSched, qCmd, qName)
	case "absent":
		// Skip when no marked line remains.
		op.OnlyIf = fmt.Sprintf("crontab -l 2>/dev/null | grep -qE -- %s", qMarker)
		op.Shell = rewrite + `crontab "$tmp"
`
	default:
		return nil, fmt.Errorf(`invalid ensure %q (want "present" or "absent")`, ensure)
	}
	return []proto.Op{{OpType: proto.OpTypeCommand, Command: op}}, nil
}

// init registers the std.cron compiler.
func init() {
	modules.Register("std.cron.Entry", modules.CompilerFunc(compileEntry))
}
