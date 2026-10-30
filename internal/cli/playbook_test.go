package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/claymod/claymod/internal/pkl"
)

// repoRoot walks up to the directory holding go.mod (the forge root).
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repo root not found")
		}
		dir = parent
	}
}

func requirePklCLI(t *testing.T) {
	t.Helper()
	if !pkl.New().Available() {
		t.Skip("pkl CLI not installed; run scripts/bootstrap-pkl.sh (see make test-full)")
	}
}

// testSchemaDir resolves the shipped schema for tests.
func testSchemaDir(t *testing.T) string {
	return filepath.Join(repoRoot(t), "pkl")
}

func TestPlaybookValidateExample(t *testing.T) {
	requirePklCLI(t)
	t.Setenv("CLAYMOD_SCHEMA_DIR", testSchemaDir(t))

	root := repoRoot(t)
	playbookFile := filepath.Join(root, "examples", "basic-setup", "playbook.pkl")
	out := new(bytes.Buffer)
	cmd := newRootCmd()
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"playbook", "validate", playbookFile})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("validate returned error: %v (output: %s)", err, out.String())
	}
	if !strings.Contains(out.String(), "playbook OK: 3 resource(s)") {
		t.Errorf("output = %q", out.String())
	}
}

func TestPlaybookPlanExample(t *testing.T) {
	requirePklCLI(t)
	t.Setenv("CLAYMOD_SCHEMA_DIR", testSchemaDir(t))

	root := repoRoot(t)
	playbookFile := filepath.Join(root, "examples", "nginx", "playbook.pkl")
	out := new(bytes.Buffer)
	cmd := newRootCmd()
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"playbook", "plan", playbookFile})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("plan returned error: %v (output: %s)", err, out.String())
	}
	log := out.String()
	// nginx.conf must be planned before nginx (dependsOn).
	confIdx := strings.Index(log, "nginx.conf [std.files.Template]")
	svcIdx := strings.Index(log, "nginx [std.service.Unit]")
	if confIdx < 0 || svcIdx < 0 || confIdx > svcIdx {
		t.Errorf("dependency order wrong:\n%s", log)
	}
}

func TestPlaybookPlanJSONGolden(t *testing.T) {
	requirePklCLI(t)
	t.Setenv("CLAYMOD_SCHEMA_DIR", testSchemaDir(t))

	root := repoRoot(t)
	playbookFile := filepath.Join(root, "examples", "basic-setup", "playbook.pkl")
	out := new(bytes.Buffer)
	cmd := newRootCmd()
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"playbook", "plan", "--json", "--host", "web01", playbookFile})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("plan --json returned error: %v (output: %s)", err, out.String())
	}
	log := out.String()
	for _, want := range []string{`"host": "web01"`, `"name": "motd"`, `"name": "app.conf"`, `"name": "logdir"`} {
		if !strings.Contains(log, want) {
			t.Errorf("JSON output missing %s:\n%s", want, log)
		}
	}
}

func TestPlaybookValidateRejectsBrokenPlaybook(t *testing.T) {
	requirePklCLI(t)
	t.Setenv("CLAYMOD_SCHEMA_DIR", testSchemaDir(t))

	// A schema-level type error: Copy requires source and dest.
	dir := t.TempDir()
	broken := filepath.Join(dir, "broken.pkl")
	content := `amends "modulepath:/claymod/base.pkl"
import "modulepath:/claymod/std/files.pkl"
resources {
  new files.Copy { name = "x" }
}
`
	if err := os.WriteFile(broken, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	out := new(bytes.Buffer)
	cmd := newRootCmd()
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"playbook", "validate", broken})
	if err := cmd.ExecuteContext(context.Background()); err == nil {
		t.Fatalf("validate accepted a broken playbook (output: %s)", out.String())
	}
}

func TestPlaybookValidateRejectsCycle(t *testing.T) {
	requirePklCLI(t)
	t.Setenv("CLAYMOD_SCHEMA_DIR", testSchemaDir(t))

	dir := t.TempDir()
	broken := filepath.Join(dir, "cycle.pkl")
	content := `amends "modulepath:/claymod/base.pkl"
import "modulepath:/claymod/std/files.pkl"
resources {
  new files.Copy { name = "a"; source = "x"; dest = "/a"; dependsOn { "b" } }
  new files.Copy { name = "b"; source = "x"; dest = "/b"; dependsOn { "a" } }
}
`
	if err := os.WriteFile(broken, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	out := new(bytes.Buffer)
	cmd := newRootCmd()
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"playbook", "validate", broken})
	err := cmd.ExecuteContext(context.Background())
	if err == nil {
		t.Fatalf("validate accepted a dependency cycle (output: %s)", out.String())
	}
	if !strings.Contains(err.Error(), "dependency cycle") {
		t.Errorf("error = %q, want dependency cycle", err.Error())
	}
}

// TestPlaybookValidateFromForeignCWD pins the CWD-independence
// guarantee: the std resolves from the embedded schema even with no
// CLAYMOD_SCHEMA_DIR and a working directory with no ./pkl.
func TestPlaybookValidateFromForeignCWD(t *testing.T) {
	requirePklCLI(t)
	t.Setenv("CLAYMOD_SCHEMA_DIR", "")

	// Capture the playbook path before leaving the repo tree.
	root := repoRoot(t)
	playbookFile := filepath.Join(root, "examples", "basic-setup", "playbook.pkl")
	t.Chdir(t.TempDir())

	out := new(bytes.Buffer)
	cmd := newRootCmd()
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"playbook", "validate", playbookFile})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("validate from foreign CWD: %v (output: %s)", err, out.String())
	}
	if !strings.Contains(out.String(), "playbook OK: 3 resource(s)") {
		t.Errorf("output = %q", out.String())
	}
}

// TestPlaybookModulePathFlag covers extra lookup dirs from the
// --module-path flag and CLAYMOD_MODULE_PATH.
func TestPlaybookModulePathFlag(t *testing.T) {
	requirePklCLI(t)
	t.Setenv("CLAYMOD_SCHEMA_DIR", "")
	t.Chdir(t.TempDir())

	// Module-path URIs resolve under the passed dir (like the real std:
	// dir "pkl" serving modulepath:/claymod/...), so the fixture needs a
	// parent holding ext/greeting.pkl.
	extRoot := t.TempDir()
	ext := filepath.Join(extRoot, "ext")
	if err := os.MkdirAll(ext, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ext, "greeting.pkl"),
		[]byte("module ext\n\ntarget = \"/etc/motd-ext\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	playbookFile := filepath.Join(dir, "playbook.pkl")
	if err := os.WriteFile(playbookFile, []byte(`amends "modulepath:/claymod/base.pkl"
import "modulepath:/claymod/std/files.pkl"
import "modulepath:/ext/greeting.pkl" as ext
hosts { "web01" }
resources {
  new files.Copy { name = "motd"; source = "motd.txt"; dest = ext.target }
}
`), 0o644); err != nil {
		t.Fatal(err)
	}

	run := func(t *testing.T, args ...string) error {
		t.Helper()
		out := new(bytes.Buffer)
		cmd := newRootCmd()
		cmd.SetOut(out)
		cmd.SetErr(out)
		cmd.SetArgs(args)
		err := cmd.ExecuteContext(context.Background())
		if err != nil && !strings.Contains(err.Error(), "Cannot find module") {
			t.Fatalf("unexpected error: %v (output: %s)", err, out.String())
		}
		return err
	}

	// Without the dir: module resolution fails, naming the searched path.
	err := run(t, "playbook", "validate", playbookFile)
	if err == nil {
		t.Fatal("validate resolved modulepath:/ext without an extra module path")
	}
	if !strings.Contains(err.Error(), "searched module path:") {
		t.Errorf("error missing searched-path annotation: %v", err)
	}

	// Via the flag: resolves.
	if err := run(t, "playbook", "validate", "--module-path", extRoot, playbookFile); err != nil {
		t.Fatalf("validate --module-path: %v", err)
	}

	// Via the env var: resolves.
	t.Setenv("CLAYMOD_MODULE_PATH", extRoot)
	if err := run(t, "playbook", "validate", playbookFile); err != nil {
		t.Fatalf("validate with CLAYMOD_MODULE_PATH: %v", err)
	}
}

// TestPlaybookValidateStdFilesExtensions evaluates all four std.files
// extensions through the real pkl CLI, catching field-name drift
// between the PKL classes and the Go compilers.
func TestPlaybookValidateStdFilesExtensions(t *testing.T) {
	requirePklCLI(t)
	t.Setenv("CLAYMOD_SCHEMA_DIR", "")
	t.Chdir(t.TempDir())

	dir := t.TempDir()
	playbookFile := filepath.Join(dir, "playbook.pkl")
	if err := os.WriteFile(playbookFile, []byte(`amends "modulepath:/claymod/base.pkl"
import "modulepath:/claymod/std/files.pkl"
hosts { "web01" }
resources {
  new files.Content {
    name = "banner"; content = "managed\n"; dest = "/etc/banner"
  }
  new files.Line {
    name = "motd-line"; path = "/etc/motd.tail"; line = "welcome"
  }
  new files.Symlink {
    name = "release"; path = "/srv/current"; target = "/srv/v1"; force = true
  }
  new files.Fetch {
    name = "ca"; url = "https://example.internal/ca.pem"; dest = "/etc/ca.pem"
  }
}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	out := new(bytes.Buffer)
	cmd := newRootCmd()
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"playbook", "validate", playbookFile})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("validate returned error: %v (output: %s)", err, out.String())
	}
	if !strings.Contains(out.String(), "playbook OK: 4 resource(s)") {
		t.Errorf("output = %q", out.String())
	}
}

// TestPlaybookValidateStdSysctlCron evaluates std.sysctl and std.cron
// through the real pkl CLI, catching field-name drift between the PKL
// classes and the Go compilers.
func TestPlaybookValidateStdSysctlCron(t *testing.T) {
	requirePklCLI(t)
	t.Setenv("CLAYMOD_SCHEMA_DIR", "")
	t.Chdir(t.TempDir())

	dir := t.TempDir()
	playbookFile := filepath.Join(dir, "playbook.pkl")
	if err := os.WriteFile(playbookFile, []byte(`amends "modulepath:/claymod/base.pkl"
import "modulepath:/claymod/std/sysctl.pkl"
import "modulepath:/claymod/std/cron.pkl"
hosts { "web01" }
resources {
  new sysctl.Sysctl {
    name = "ip-forward"; key = "net.ipv4.ip_forward"; value = "1"
  }
  new cron.Entry {
    name = "nightly"; schedule = "0 3 * * *"; command = "/usr/local/bin/backup.sh"
  }
  new cron.Entry {
    name = "stale"; schedule = "@daily"; command = "/usr/local/bin/old.sh"; ensure = "absent"
  }
}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	out := new(bytes.Buffer)
	cmd := newRootCmd()
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"playbook", "validate", playbookFile})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("validate returned error: %v (output: %s)", err, out.String())
	}
	if !strings.Contains(out.String(), "playbook OK: 3 resource(s)") {
		t.Errorf("output = %q", out.String())
	}
}

func TestPlaybookMissingFile(t *testing.T) {
	out := new(bytes.Buffer)
	cmd := newRootCmd()
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"playbook", "validate", "/nope/missing.pkl"})
	if err := cmd.ExecuteContext(context.Background()); err == nil {
		t.Fatal("validate accepted a missing playbook")
	}
}
