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
