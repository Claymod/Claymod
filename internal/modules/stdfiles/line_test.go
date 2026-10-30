package stdfiles

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/claymod/claymod/internal/playbook"
)

// runLineRecipe compiles a Line resource and executes its generated
// shell under /bin/sh — the black-box proof that the recipes work.
func runLineRecipe(t *testing.T, path, line, ensure string) (exitCode int, stderr string) {
	t.Helper()
	raw, err := json.Marshal(LineResource{Type: "std.files.Line", Name: "x", Path: path, Line: line, Ensure: ensure})
	if err != nil {
		t.Fatal(err)
	}
	var res playbook.Resource
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatal(err)
	}
	ops, err := compileLine(res, playbook.RenderContext{Vars: map[string]string{}})
	if err != nil {
		t.Fatalf("compileLine: %v", err)
	}
	return runShell(t, ops[0].Command.Shell)
}

// runSymlinkRecipe compiles a Symlink resource and runs its shell.
func runSymlinkRecipe(t *testing.T, path, target string, force bool) (exitCode int, output string, shell string) {
	t.Helper()
	raw, err := json.Marshal(SymlinkResource{Type: "std.files.Symlink", Name: "x", Path: path, Target: target, Force: force})
	if err != nil {
		t.Fatal(err)
	}
	var res playbook.Resource
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatal(err)
	}
	ops, err := compileSymlink(res, playbook.RenderContext{Vars: map[string]string{}})
	if err != nil {
		t.Fatalf("compileSymlink: %v", err)
	}
	code, out := runShell(t, ops[0].Command.Shell)
	return code, out, ops[0].Command.Shell
}

// runShell executes shell under /bin/sh, capturing stderr+stdout.
func runShell(t *testing.T, shell string) (exitCode int, output string) {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", shell)
	var buf strings.Builder
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	code := 0
	if err := cmd.Run(); err != nil {
		code = cmd.ProcessState.ExitCode()
	}
	return code, buf.String()
}

func TestLineAppendPreservesUnfinishedLastLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "conf")

	cases := []struct {
		name    string
		begin   string // file content before ("" with missing=false = empty file)
		missing bool   // start with no file at all
		want    string // exact content after
	}{
		{"missing file", "", true, "hello\n"},
		{"empty file", "", false, "hello\n"},
		{"no trailing newline", "abc", false, "abc\nhello\n"},
		{"trailing newline", "abc\n", false, "abc\nhello\n"},
		{"blank last line", "abc\n\n", false, "abc\n\nhello\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.missing {
				if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, []byte(tc.begin), 0o644); err != nil {
				t.Fatal(err)
			}
			code, stderr := runLineRecipe(t, path, "hello", "present")
			if code != 0 {
				t.Fatalf("recipe exited %d: %s", code, stderr)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Errorf("file = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSymlinkRefusalDoesNotExecuteSubstitution pins the injection fix:
// the fail-loudly branch treats the path as data, never executes
// command substitution embedded in it.
func TestSymlinkRefusalDoesNotExecuteSubstitution(t *testing.T) {
	dir := t.TempDir()
	evil := filepath.Join(dir, `$(touch pwned)"x`)
	if err := os.WriteFile(evil, []byte("occupied"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	code, out, shell := runSymlinkRecipe(t, evil, target, false)
	if code == 0 {
		t.Fatalf("refusal branch exited 0 (output: %s)", out)
	}
	if !strings.Contains(out, "not a symlink") {
		t.Errorf("refusal output = %q, want the not-a-symlink message", out)
	}
	if strings.Contains(shell, `echo "`) {
		t.Fatalf("recipe interpolates the path inside a double-quoted message: %q", shell)
	}
	if _, err := os.Stat(filepath.Join(dir, "pwned")); err == nil {
		t.Fatal("command substitution inside the path was executed")
	}
	// The occupied file must be untouched.
	data, err := os.ReadFile(evil)
	if err != nil || string(data) != "occupied" {
		t.Errorf("occupied file changed: %q, err %v", data, err)
	}
}

// TestSymlinkRefusalHappyPath checks the non-evil refusal branch end to
// end: a regular file is refused, a symlink is relinked.
func TestSymlinkRefusalBranches(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Regular file, no force: refused, file intact.
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("precious"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := runSymlinkRecipe(t, file, target, false); code == 0 {
		t.Errorf("refusal exited 0 (output: %s)", out)
	}
	if data, err := os.ReadFile(file); err != nil || string(data) != "precious" {
		t.Errorf("refused file changed: %q, err %v", data, err)
	}

	// Both sides resolved (macOS maps /var -> /private/var in temp paths).
	wantTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}

	// Regular file, force: replaced by the symlink.
	if code, out, _ := runSymlinkRecipe(t, file, target, true); code != 0 {
		t.Fatalf("force recipe exited %d (output: %s)", code, out)
	}
	if real, err := filepath.EvalSymlinks(file); err != nil || real != wantTarget {
		t.Errorf("forced symlink resolves to %q (err %v), want %q", real, err, wantTarget)
	}

	// Wrong-target symlink, no force: relinked.
	link := filepath.Join(dir, "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := runSymlinkRecipe(t, link, target, false); code != 0 {
		t.Fatalf("relink recipe exited %d (output: %s)", code, out)
	}
	if real, err := filepath.EvalSymlinks(link); err != nil || real != wantTarget {
		t.Errorf("relinked symlink resolves to %q (err %v), want %q", real, err, wantTarget)
	}
}
