package stdusers

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/claymod/claymod/internal/modules"
	"github.com/claymod/claymod/internal/playbook"
	"github.com/claymod/claymod/internal/proto"
)

// fakeBin writes an executable script on a PATH front dir.
func fakeBin(t *testing.T, dir, name, script string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

// fakeUserlandFshims installs PATH fakes for the shadow userland and a
// store for the fake `id`: users recorded in the store "exist".
func fakeUserland(t *testing.T) (binDir, store, log string) {
	t.Helper()
	binDir = t.TempDir()
	store = filepath.Join(t.TempDir(), "users")
	log = filepath.Join(t.TempDir(), "calls")

	record := "#!/bin/sh\necho \"$0 $*\" >> \"" + log + "\"\nexit 0\n"
	for _, name := range []string{"useradd", "userdel", "groupadd", "groupdel", "adduser", "deluser", "addgroup", "delgroup"} {
		fakeBin(t, binDir, name, record)
	}
	// id -u NAME: present when the store lists the name.
	fakeBin(t, binDir, "id", "#!/bin/sh\n"+
		"[ \"$1\" = \"-u\" ] || exit 2\n"+
		"grep -qxF \"$2\" \""+store+"\" 2>/dev/null && { echo 1001; exit 0; }\n"+
		"exit 1\n")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return binDir, store, log
}

// runOp simulates the agent's guard ordering for one compiled op.
func runOp(t *testing.T, cmd *proto.CommandOp) (ran bool, output string, errCode int) {
	t.Helper()
	guard := func(g string) bool {
		c := exec.Command("/bin/sh", "-c", g)
		return c.Run() == nil
	}
	if cmd.OnlyIf != "" && !guard(cmd.OnlyIf) {
		return false, "skipped: only_if", 0
	}
	if cmd.UnlessIf != "" && guard(cmd.UnlessIf) {
		return false, "skipped: unless_if", 0
	}
	c := exec.Command("/bin/sh", "-c", cmd.Shell)
	out, err := c.CombinedOutput()
	if err != nil {
		return true, string(out), c.ProcessState.ExitCode()
	}
	return true, string(out), 0
}

func compile(t *testing.T, doc string) *proto.CommandOp {
	t.Helper()
	var res playbook.Resource
	if err := json.Unmarshal([]byte(doc), &res); err != nil {
		t.Fatal(err)
	}
	ops, err := modulesCompile(res)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return ops[0].Command
}

func readLog(t *testing.T, log string) string {
	t.Helper()
	data, err := os.ReadFile(log)
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatal(err)
	}
	return string(data)
}

func TestUsersPresentGolden(t *testing.T) {
	cmd := compile(t, `{"type":"std.users.Present","name":"svc-app","uid":"1500","group":"app","shell":"/usr/sbin/nologin","system":true,"createHome":true}`)
	if cmd.UnlessIf != "id -u 'svc-app' >/dev/null 2>&1" {
		t.Errorf("unlessIf = %q", cmd.UnlessIf)
	}
	for _, want := range []string{
		"command -v useradd",
		"useradd -r -m -s '/usr/sbin/nologin' -u 1500 -g 'app' 'svc-app'",
		"command -v adduser",
		"adduser -D -S -s '/usr/sbin/nologin' -u 1500 -G 'app' 'svc-app'",
	} {
		if !strings.Contains(cmd.Shell, want) {
			t.Errorf("shell = %q, want it to contain %q", cmd.Shell, want)
		}
	}

	// createHome=false flips -m to -M and adds busybox -H.
	cmd = compile(t, `{"type":"std.users.Present","name":"svc-app","createHome":false}`)
	if !strings.Contains(cmd.Shell, "useradd -M 'svc-app'") {
		t.Errorf("no-home useradd line missing: %q", cmd.Shell)
	}
	if !strings.Contains(cmd.Shell, "adduser -D -H 'svc-app'") {
		t.Errorf("no-home adduser line missing: %q", cmd.Shell)
	}
}

func TestUsersAbsentGolden(t *testing.T) {
	cmd := compile(t, `{"type":"std.users.Absent","name":"old","removeHome":true}`)
	if cmd.OnlyIf != "id -u 'old' >/dev/null 2>&1" {
		t.Errorf("onlyIf = %q", cmd.OnlyIf)
	}
	if !strings.Contains(cmd.Shell, "userdel -r 'old'") || !strings.Contains(cmd.Shell, "deluser --remove-home 'old'") {
		t.Errorf("shell = %q", cmd.Shell)
	}
	cmd = compile(t, `{"type":"std.users.Absent","name":"old"}`)
	if strings.Contains(cmd.Shell, "-r") || strings.Contains(cmd.Shell, "--remove-home") {
		t.Errorf("default absent must keep the home: %q", cmd.Shell)
	}
}

func TestUsersGroupGolden(t *testing.T) {
	cmd := compile(t, `{"type":"std.users.Group","name":"app-team","gid":"2000"}`)
	if cmd.UnlessIf != `grep -q '^app-team:' /etc/group 2>/dev/null` {
		t.Errorf("unlessIf = %q", cmd.UnlessIf)
	}
	if !strings.Contains(cmd.Shell, "groupadd -g 2000 'app-team'") ||
		!strings.Contains(cmd.Shell, "addgroup -g 2000 'app-team'") {
		t.Errorf("shell = %q", cmd.Shell)
	}
	cmd = compile(t, `{"type":"std.users.Group","name":"app-team","ensure":"absent"}`)
	if cmd.OnlyIf == "" || !strings.Contains(cmd.Shell, "groupdel 'app-team'") {
		t.Errorf("absent op = %+v", cmd)
	}
}

func TestUsersAuthorizedKeyGolden(t *testing.T) {
	cmd := compile(t, `{"type":"std.users.AuthorizedKey","name":"k","user":"svc-app","key":"ssh-ed25519 AAAA x@y"}`)
	if !strings.Contains(cmd.UnlessIf, "awk -F: -v u='svc-app'") ||
		!strings.Contains(cmd.UnlessIf, `grep -qxF -- 'ssh-ed25519 AAAA x@y'`) {
		t.Errorf("unlessIf = %q", cmd.UnlessIf)
	}
	for _, want := range []string{
		"mkdir -p \"$h/.ssh\"",
		"chmod 700 \"$h/.ssh\"",
		"chmod 600 \"$k\"",
		`chown -R "$(id -u 'svc-app'):$(id -g 'svc-app')" "$h/.ssh"`,
		`tail -c 1 "$k"`,
	} {
		if !strings.Contains(cmd.Shell, want) {
			t.Errorf("shell = %q, want it to contain %q", cmd.Shell, want)
		}
	}
}

func TestUsersPresentBehavioral(t *testing.T) {
	_, store, log := fakeUserland(t)

	// First run: guard says absent, useradd runs with the wanted flags
	// (options first, name last — busybox does not permute argv).
	op := compile(t, `{"type":"std.users.Present","name":"cm-test","system":true,"shell":"/bin/false","createHome":true}`)
	ran, out, code := runOp(t, op)
	if !ran || code != 0 {
		t.Fatalf("present: ran=%v code=%d output=%s", ran, code, out)
	}
	if l := readLog(t, log); !strings.Contains(l, "useradd -r -m -s /bin/false cm-test") {
		t.Errorf("useradd call log = %q", l)
	}
	// The fake useradd marks the user present; the second run skips.
	if err := os.WriteFile(store, []byte("cm-test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if ran, out, _ := runOp(t, op); ran {
		t.Fatalf("second present run not skipped: %s", out)
	}
}

func TestUsersAbsentBehavioral(t *testing.T) {
	_, store, log := fakeUserland(t)

	// Absent of an existing user runs userdel -r.
	op := compile(t, `{"type":"std.users.Absent","name":"cm-gone","removeHome":true}`)
	if err := os.WriteFile(store, []byte("cm-gone\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ran, out, code := runOp(t, op)
	if !ran || code != 0 {
		t.Fatalf("absent: ran=%v code=%d output=%s", ran, code, out)
	}
	if l := readLog(t, log); !strings.Contains(l, "userdel -r cm-gone") {
		t.Errorf("userdel call log = %q", l)
	}

	// Absent of a missing user is skipped by the guard.
	op = compile(t, `{"type":"std.users.Absent","name":"cm-never-existed"}`)
	if ran, out, _ := runOp(t, op); ran {
		t.Fatalf("absent of missing user ran: %s", out)
	}
}

func TestUsersGroupBehavioral(t *testing.T) {
	_, _, log := fakeUserland(t)

	// A group NOT in the real /etc/group: groupadd runs.
	op := compile(t, `{"type":"std.users.Group","name":"cm-test-grp","gid":"2999"}`)
	ran, out, code := runOp(t, op)
	if !ran || code != 0 {
		t.Fatalf("group present: ran=%v code=%d output=%s", ran, code, out)
	}
	if l := readLog(t, log); !strings.Contains(l, "groupadd -g 2999 cm-test-grp") {
		t.Errorf("groupadd call log = %q", l)
	}

	// A group that EXISTS in the real /etc/group ("daemon" on Linux and
	// macOS): absent runs the (fake) groupdel.
	op = compile(t, `{"type":"std.users.Group","name":"daemon","ensure":"absent"}`)
	ran, out, code = runOp(t, op)
	if !ran || code != 0 {
		t.Fatalf("group absent: ran=%v code=%d output=%s", ran, code, out)
	}
	if l := readLog(t, log); !strings.Contains(l, "groupdel daemon") {
		t.Errorf("groupdel call log = %q", l)
	}

	// Absent of a missing group is skipped.
	op = compile(t, `{"type":"std.users.Group","name":"cm-no-such-grp","ensure":"absent"}`)
	if ran, out, _ := runOp(t, op); ran {
		t.Fatalf("absent of missing group ran: %s", out)
	}
}

func TestUsersAuthorizedKeyUnknownUserFails(t *testing.T) {
	// No fakes: a user absent from the real /etc/passwd fails loudly.
	op := compile(t, `{"type":"std.users.AuthorizedKey","name":"k","user":"cm-no-such-user","key":"ssh-ed25519 AAAA"}`)
	ran, out, code := runOp(t, op)
	if !ran || code == 0 {
		t.Fatalf("unknown-user key ran=%v code=%d output=%s", ran, code, out)
	}
	if !strings.Contains(out, "not found in /etc/passwd") {
		t.Errorf("output = %q, want the not-found message", out)
	}
}

func TestUsersAuthorizedKeyBehavioral(t *testing.T) {
	fakeUserland(t)
	// A fake awk answers the /etc/passwd home lookup with a temp home
	// and passes everything else through to the real awk.
	home := t.TempDir()
	binDir := t.TempDir()
	fakeBin(t, binDir, "awk", "#!/bin/sh\n"+
		"for a in \"$@\"; do\n"+
		"  case \"$a\" in /etc/passwd) echo \""+home+"\"; exit 0 ;; esac\n"+
		"done\n"+
		"exec "+awkPath()+" \"$@\"\n")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	op := compile(t, `{"type":"std.users.AuthorizedKey","name":"k","user":"cm-test","key":"ssh-ed25519 AAAATEST"}`)
	ran, out, code := runOp(t, op)
	if !ran || code != 0 {
		t.Fatalf("authorized key: ran=%v code=%d output=%s", ran, code, out)
	}
	keyFile := filepath.Join(home, ".ssh", "authorized_keys")
	data, err := os.ReadFile(keyFile)
	if err != nil || string(data) != "ssh-ed25519 AAAATEST\n" {
		t.Fatalf("authorized_keys = %q, err %v", data, err)
	}
	if info, err := os.Stat(keyFile); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("authorized_keys mode = %v, err %v", info.Mode(), err)
	}
	if info, err := os.Stat(filepath.Join(home, ".ssh")); err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf(".ssh mode = %v, err %v", info.Mode(), err)
	}

	// Second run: the guard sees the key and skips.
	if ran, out, _ := runOp(t, op); ran {
		t.Fatalf("second key run not skipped: %s", out)
	}
}

// awkPath resolves the real awk for the fake shim.
func awkPath() string {
	for _, p := range []string{"/usr/bin/awk", "/bin/awk", "/usr/bin/gawk", "/usr/bin/mawk"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "awk"
}

// modulesCompile dispatches through the shared registry (this
// package's init registers the std.users compilers).
func modulesCompile(res playbook.Resource) ([]proto.Op, error) {
	return modules.Compile(res, playbook.RenderContext{Vars: map[string]string{}})
}
