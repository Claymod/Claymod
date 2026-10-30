package cli

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fixtureLibProject builds a git library repo (module acme.baseline,
// tagged v1.0.0) and a playbook repo with a claymod.project.yaml pinning
// it plus a local schemaPath. Returns (projectDir, libRepo).
func fixtureLibProject(t *testing.T) (string, string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git CLI not installed")
	}
	// Isolate the library cache per test (CLAYMOD_CACHE_DIR override).
	t.Setenv("CLAYMOD_CACHE_DIR", t.TempDir())
	root := t.TempDir()
	repo := filepath.Join(root, "acme-lib")
	if err := os.MkdirAll(filepath.Join(repo, "pkl", "acme"), 0o755); err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) {
		full := append([]string{"-c", "user.email=t@t", "-c", "user.name=t", "-C", repo}, args...)
		if out, err := exec.Command("git", full...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	if err := os.WriteFile(filepath.Join(repo, "pkl", "acme", "baseline.pkl"),
		[]byte("module acme.baseline\n\nmotd = \"acme v1\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("init", "--quiet")
	git("add", "-A")
	git("commit", "--quiet", "-m", "v1")
	git("tag", "v1.0.0")

	projectDir := filepath.Join(root, "playbooks")
	if err := os.MkdirAll(filepath.Join(projectDir, "schema"), 0o755); err != nil {
		t.Fatal(err)
	}
	project := "version: 1\n" +
		"schemaPaths: [\"./schema\"]\n" +
		"libraries:\n" +
		"  - name: acme\n" +
		"    git: " + repo + "\n" +
		"    ref: v1.0.0\n" +
		"    path: pkl\n"
	if err := os.WriteFile(filepath.Join(projectDir, "claymod.project.yaml"), []byte(project), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "schema", "extra.pkl"),
		[]byte("module extra\n\nsuffix = \"!\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return projectDir, repo
}

func TestLibListAndSync(t *testing.T) {
	t.Setenv("CLAYMOD_SCHEMA_DIR", "")
	projectDir, _ := fixtureLibProject(t)

	// list before sync: not synced.
	out := new(bytes.Buffer)
	cmd := newRootCmd()
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"lib", "list", "--project", filepath.Join(projectDir, "claymod.project.yaml")})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("lib list: %v (output: %s)", err, out.String())
	}
	if !strings.Contains(out.String(), "not synced") || !strings.Contains(out.String(), "acme") {
		t.Errorf("list output = %q", out.String())
	}

	// sync: clones and reports the commit.
	out = new(bytes.Buffer)
	cmd = newRootCmd()
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"lib", "sync", "--project", filepath.Join(projectDir, "claymod.project.yaml")})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("lib sync: %v (output: %s)", err, out.String())
	}
	if !strings.Contains(out.String(), "acme") {
		t.Errorf("sync output = %q", out.String())
	}

	// list after sync: cached (12-char short sha).
	out = new(bytes.Buffer)
	cmd = newRootCmd()
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"lib", "list", "--project", filepath.Join(projectDir, "claymod.project.yaml")})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("lib list after sync: %v (output: %s)", err, out.String())
	}
	if !strings.Contains(out.String(), "cached @ ") {
		t.Errorf("list output after sync = %q", out.String())
	}
}

func TestLibSyncOfflineCold(t *testing.T) {
	t.Setenv("CLAYMOD_SCHEMA_DIR", "")
	projectDir, _ := fixtureLibProject(t)

	out := new(bytes.Buffer)
	cmd := newRootCmd()
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"lib", "sync", "--offline", "--project", filepath.Join(projectDir, "claymod.project.yaml")})
	err := cmd.ExecuteContext(context.Background())
	if err == nil {
		t.Fatalf("offline sync accepted a cold cache (output: %s)", out.String())
	}
	if !strings.Contains(err.Error(), "offline") {
		t.Errorf("error = %q, want an offline message", err.Error())
	}
}

// TestPlaybookValidateWithProject is the integration proof: a playbook
// above no claymod.project.yaml of its own imports modules from BOTH a
// synced git library (modulepath:/acme/…) and a project schemaPath —
// resolved automatically, from any working directory.
func TestPlaybookValidateWithProject(t *testing.T) {
	requirePklCLI(t)
	t.Setenv("CLAYMOD_SCHEMA_DIR", "")
	t.Setenv("CLAYMOD_MODULE_PATH", "")
	projectDir, _ := fixtureLibProject(t)

	playbookFile := filepath.Join(projectDir, "sub", "playbook.pkl")
	if err := os.MkdirAll(filepath.Dir(playbookFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(playbookFile, []byte(`amends "modulepath:/claymod/base.pkl"
import "modulepath:/claymod/std/files.pkl"
import "modulepath:/acme/baseline.pkl" as acme
import "modulepath:/extra.pkl" as extra
hosts { "web01" }
resources {
  new files.Content {
    name = "motd"; content = acme.motd + extra.suffix; dest = "/etc/motd"
  }
}
`), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Chdir(t.TempDir()) // any working directory
	out := new(bytes.Buffer)
	cmd := newRootCmd()
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"playbook", "validate", playbookFile})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("validate with project: %v (output: %s)", err, out.String())
	}
	if !strings.Contains(out.String(), "playbook OK: 1 resource(s)") {
		t.Errorf("output = %q", out.String())
	}
}
