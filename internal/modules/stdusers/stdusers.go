// Package stdusers compiles std.users.* resources into Command ops.
// The concept of Unix users is universal; the tool names are not. The
// recipes prefer the shadow userland (useradd/userdel/groupadd/
// groupdel — Debian, RHEL, Arch, ...) and fall back to BusyBox
// (adduser/deluser/addgroup/delgroup — stock Alpine). The branch order
// matters: Debian also ships a perl adduser with different flags, but
// useradd exists there, so the BusyBox branch only wins on
// busybox-only systems.
package stdusers

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/claymod/claymod/internal/modules"
	"github.com/claymod/claymod/internal/modules/shell"
	"github.com/claymod/claymod/internal/playbook"
	"github.com/claymod/claymod/internal/proto"
)

// nameRe is the conservative Unix login/group charset (also rules out
// "-" leading dashes and every shell-hostile character).
var nameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

var numericRe = regexp.MustCompile(`^[0-9]+$`)

// PresentResource mirrors the std.users.Present PKL class.
type PresentResource struct {
	Type       string `json:"type"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
	Group      string `json:"group"`
	Shell      string `json:"shell"`
	System     bool   `json:"system"`
	CreateHome bool   `json:"createHome"`
}

// AbsentResource mirrors the std.users.Absent PKL class.
type AbsentResource struct {
	Type       string `json:"type"`
	Name       string `json:"name"`
	RemoveHome bool   `json:"removeHome"`
}

// GroupResource mirrors the std.users.Group PKL class.
type GroupResource struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	GID    string `json:"gid"`
	Ensure string `json:"ensure"`
}

// AuthorizedKeyResource mirrors the std.users.AuthorizedKey PKL class.
type AuthorizedKeyResource struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	User   string `json:"user"`
	Key    string `json:"key"`
	Ensure string `json:"ensure"`
}

// validateName checks a login/group name.
func validateName(field, name string) error {
	if name == "" {
		return fmt.Errorf("%s is required", field)
	}
	if !nameRe.MatchString(name) {
		return fmt.Errorf("%s %q is not a valid Unix name (lowercase letters, digits, _ and -, max 32, no leading dash)", field, name)
	}
	return nil
}

// validateID checks an optional numeric uid/gid.
func validateID(field, id string) error {
	if id == "" {
		return nil
	}
	if !numericRe.MatchString(id) {
		return fmt.Errorf("%s must be numeric or empty, got %q", field, id)
	}
	return nil
}

// requireSingleLine rejects values that would break the entry line.
func requireSingleLine(field, v string) error {
	if v == "" {
		return fmt.Errorf("%s is required", field)
	}
	if strings.Contains(v, "\n") {
		return fmt.Errorf("%s must be a single line", field)
	}
	return nil
}

// homeLookup is the POSIX home-directory lookup (pure /etc/passwd
// parsing — no getent dependency, busybox awk included).
func homeLookup(user string) string {
	return fmt.Sprintf(`h=$(awk -F: -v u=%s '$1 == u { print $6; exit }' /etc/passwd)`, shell.Quote(user))
}

// compilePresent emits a guarded op creating the user when missing.
// An existing user is left untouched (unlessIf), so the resource is
// idempotent and never "fixes" drifted attributes in v1.
func compilePresent(res playbook.Resource, ctx playbook.RenderContext) ([]proto.Op, error) {
	var r PresentResource
	if err := modules.DecodeResource(res, &r); err != nil {
		return nil, err
	}
	if err := validateName("name", r.Name); err != nil {
		return nil, err
	}
	if err := validateID("uid", r.UID); err != nil {
		return nil, err
	}
	if err := validateName("group", r.Group); err != nil && r.Group != "" {
		return nil, err
	}
	if r.Shell != "" {
		if err := requireSingleLine("shell", r.Shell); err != nil {
			return nil, err
		}
	}
	qName := shell.Quote(r.Name)

	// useradd flags (shadow userland).
	var uargs []string
	if r.System {
		uargs = append(uargs, "-r")
	}
	if r.CreateHome {
		uargs = append(uargs, "-m")
	} else {
		uargs = append(uargs, "-M")
	}
	if r.Shell != "" {
		uargs = append(uargs, "-s", shell.Quote(r.Shell))
	}
	if r.UID != "" {
		uargs = append(uargs, "-u", r.UID)
	}
	if r.Group != "" {
		uargs = append(uargs, "-g", shell.Quote(r.Group))
	}
	// busybox adduser flags (a different tool with the same concept).
	var aargs []string
	aargs = append(aargs, "-D") // created with a locked password, like useradd's default
	if r.System {
		aargs = append(aargs, "-S")
	}
	if !r.CreateHome {
		aargs = append(aargs, "-H")
	}
	if r.Shell != "" {
		aargs = append(aargs, "-s", shell.Quote(r.Shell))
	}
	if r.UID != "" {
		aargs = append(aargs, "-u", r.UID)
	}
	if r.Group != "" {
		aargs = append(aargs, "-G", shell.Quote(r.Group))
	}

	shellText := fmt.Sprintf(`id -u %s >/dev/null 2>&1 && exit 0
if command -v useradd >/dev/null 2>&1; then
  useradd %s %s
elif command -v adduser >/dev/null 2>&1; then
  adduser %s %s
else
  echo "std.users: no useradd or adduser available to create %s" >&2
  exit 1
fi`, qName, strings.Join(uargs, " "), qName, strings.Join(aargs, " "), qName, qName)
	return []proto.Op{{
		OpType: proto.OpTypeCommand,
		Command: &proto.CommandOp{
			UnlessIf: fmt.Sprintf("id -u %s >/dev/null 2>&1", qName),
			Shell:    shellText,
		},
	}}, nil
}

// compileAbsent emits a guarded op removing the user when present.
func compileAbsent(res playbook.Resource, ctx playbook.RenderContext) ([]proto.Op, error) {
	var r AbsentResource
	if err := modules.DecodeResource(res, &r); err != nil {
		return nil, err
	}
	if err := validateName("name", r.Name); err != nil {
		return nil, err
	}
	qName := shell.Quote(r.Name)
	shellText := fmt.Sprintf(`if command -v userdel >/dev/null 2>&1; then
  userdel %s %s
elif command -v deluser >/dev/null 2>&1; then
  deluser %s %s
else
  echo "std.users: no userdel or deluser available to remove %s" >&2
  exit 1
fi`,
		homeRemoveFlagUserdel(r.RemoveHome), qName,
		homeRemoveFlagDeluser(r.RemoveHome), qName, qName)
	return []proto.Op{{
		OpType: proto.OpTypeCommand,
		Command: &proto.CommandOp{
			OnlyIf: fmt.Sprintf("id -u %s >/dev/null 2>&1", qName),
			Shell:  shellText,
		},
	}}, nil
}

func homeRemoveFlagUserdel(remove bool) string {
	if remove {
		return "-r"
	}
	return ""
}

func homeRemoveFlagDeluser(remove bool) string {
	if remove {
		return "--remove-home"
	}
	return ""
}

// compileGroup emits a guarded op managing a group in /etc/group terms.
func compileGroup(res playbook.Resource, ctx playbook.RenderContext) ([]proto.Op, error) {
	var r GroupResource
	if err := modules.DecodeResource(res, &r); err != nil {
		return nil, err
	}
	if err := validateName("name", r.Name); err != nil {
		return nil, err
	}
	if err := validateID("gid", r.GID); err != nil {
		return nil, err
	}
	ensure := r.Ensure
	if ensure == "" {
		ensure = "present"
	}
	qName := shell.Quote(r.Name)
	groupPresent := fmt.Sprintf(`grep -q %s /etc/group 2>/dev/null`, shell.Quote("^"+r.Name+":"))

	var gargs, aargs string
	if r.GID != "" {
		gargs = "-g " + r.GID
		aargs = "-g " + r.GID
	}
	op := &proto.CommandOp{}
	switch ensure {
	case "present":
		op.UnlessIf = groupPresent
		op.Shell = fmt.Sprintf(`if command -v groupadd >/dev/null 2>&1; then
  groupadd %s %s
elif command -v addgroup >/dev/null 2>&1; then
  addgroup %s %s
else
  echo "std.users: no groupadd or addgroup available to create %s" >&2
  exit 1
fi`, gargs, qName, aargs, qName, qName)
	case "absent":
		op.OnlyIf = groupPresent
		op.Shell = fmt.Sprintf(`if command -v groupdel >/dev/null 2>&1; then
  groupdel %s
elif command -v delgroup >/dev/null 2>&1; then
  delgroup %s
else
  echo "std.users: no groupdel or delgroup available to remove %s" >&2
  exit 1
fi`, qName, qName, qName)
	default:
		return nil, fmt.Errorf(`invalid ensure %q (want "present" or "absent")`, ensure)
	}
	return []proto.Op{{OpType: proto.OpTypeCommand, Command: op}}, nil
}

// compileAuthorizedKey manages one key line in the user's
// authorized_keys (home looked up in /etc/passwd). Idempotent per key:
// the guard greps for the exact key, and other keys are never touched.
func compileAuthorizedKey(res playbook.Resource, ctx playbook.RenderContext) ([]proto.Op, error) {
	var r AuthorizedKeyResource
	if err := modules.DecodeResource(res, &r); err != nil {
		return nil, err
	}
	if err := validateName("user", r.User); err != nil {
		return nil, err
	}
	if err := requireSingleLine("key", r.Key); err != nil {
		return nil, err
	}
	ensure := r.Ensure
	if ensure == "" {
		ensure = "present"
	}
	qUser, qKey := shell.Quote(r.User), shell.Quote(r.Key)
	lookup := homeLookup(r.User)
	// present: skip when the exact key is already in the user's file.
	guard := fmt.Sprintf(`%s
[ -n "$h" ] && grep -qxF -- %s "$h/.ssh/authorized_keys" 2>/dev/null`, lookup, qKey)

	op := &proto.CommandOp{}
	switch ensure {
	case "present":
		op.UnlessIf = guard
		op.Shell = fmt.Sprintf(`%s
[ -n "$h" ] || { echo "std.users: user %s not found in /etc/passwd" >&2; exit 1; }
k="$h/.ssh/authorized_keys"
mkdir -p "$h/.ssh"
chmod 700 "$h/.ssh"
[ -z "$(tail -c 1 "$k" 2>/dev/null)" ] || printf '\n' >> "$k"
grep -qxF -- %s "$k" 2>/dev/null || printf '%%s\n' %s >> "$k"
chmod 600 "$k"
chown -R "$(id -u %s):$(id -g %s)" "$h/.ssh"`, lookup, qUser, qKey, qKey, qUser, qUser)
	case "absent":
		op.OnlyIf = guard
		op.Shell = fmt.Sprintf(`%s
[ -n "$h" ] || exit 0
k="$h/.ssh/authorized_keys"
tmp=$(mktemp) || exit 1
trap 'rm -f "$tmp"' EXIT
grep -vxF -- %s "$k" > "$tmp" || true
cat "$tmp" > "$k"
chmod 600 "$k"
chown -R "$(id -u %s):$(id -g %s)" "$h/.ssh"`, lookup, qKey, qUser, qUser)
	default:
		return nil, fmt.Errorf(`invalid ensure %q (want "present" or "absent")`, ensure)
	}
	return []proto.Op{{OpType: proto.OpTypeCommand, Command: op}}, nil
}

// init registers the std.users compilers.
func init() {
	modules.Register("std.users.Present", modules.CompilerFunc(compilePresent))
	modules.Register("std.users.Absent", modules.CompilerFunc(compileAbsent))
	modules.Register("std.users.Group", modules.CompilerFunc(compileGroup))
	modules.Register("std.users.AuthorizedKey", modules.CompilerFunc(compileAuthorizedKey))
}
