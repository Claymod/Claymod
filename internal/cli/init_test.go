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

// runInit drives `playbook init <dir>` and returns its output.
func runInit(t *testing.T, dir string) (string, error) {
	t.Helper()
	out := new(bytes.Buffer)
	cmd := newRootCmd()
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"playbook", "init", dir})
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

func TestPlaybookInitCreatesValidScaffold(t *testing.T) {
	t.Setenv("CLAYMOD_SCHEMA_DIR", "")
	dir := filepath.Join(t.TempDir(), "my-playbook")

	out, err := runInit(t, dir)
	if err != nil {
		t.Fatalf("init returned error: %v (output: %s)", err, out)
	}
	for _, rel := range []string{
		"playbook.pkl",
		filepath.Join("files", "motd.txt"),
		filepath.Join("files", "hello.tmpl"),
		"claymod.project.yaml",
	} {
		if _, err := os.Stat(filepath.Join(dir, rel)); err != nil {
			t.Errorf("scaffold missing %s: %v", rel, err)
		}
	}
	if !strings.Contains(out, "created  playbook.pkl") || !strings.Contains(out, "next: claymod playbook validate") {
		t.Errorf("output = %q", out)
	}

	// The scaffold is valid out of the box (real pkl evaluation).
	if pklAvailable := pklAvailableForTest(); pklAvailable {
		vout := new(bytes.Buffer)
		vcmd := newRootCmd()
		vcmd.SetOut(vout)
		vcmd.SetErr(vout)
		vcmd.SetArgs([]string{"playbook", "validate", filepath.Join(dir, "playbook.pkl")})
		if err := vcmd.ExecuteContext(context.Background()); err != nil {
			t.Fatalf("scaffold does not validate: %v (output: %s)", err, vout.String())
		}
		if !strings.Contains(vout.String(), "playbook OK: 3 resource(s)") {
			t.Errorf("validate output = %q", vout.String())
		}
	}
}

// pklAvailableForTest reports whether the pkl CLI is on PATH (the
// scaffold-validation part of the init test needs it).
func pklAvailableForTest() bool {
	_, err := exec.LookPath("pkl")
	return err == nil
}

func TestPlaybookInitRefusesExistingPlaybook(t *testing.T) {
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "playbook.pkl")
	if err := os.WriteFile(sentinel, []byte("PRECIOUS PLAYBOOK\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := runInit(t, dir)
	if err == nil {
		t.Fatalf("init accepted an existing playbook (output: %s)", out)
	}
	if !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Errorf("error = %q, want a refusing-to-overwrite message", err.Error())
	}
	// Nothing was touched: the file keeps its content, no files/ dir.
	data, err := os.ReadFile(sentinel)
	if err != nil || string(data) != "PRECIOUS PLAYBOOK\n" {
		t.Errorf("existing playbook changed: %q, err %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "files")); !os.IsNotExist(err) {
		t.Errorf("init created files/ despite refusing: %v", err)
	}
}

func TestPlaybookInitSkipsProjectWhenParentHasOne(t *testing.T) {
	t.Setenv("CLAYMOD_SCHEMA_DIR", "")
	parent := t.TempDir()
	project := "version: 1\nlibraries: []\n"
	if err := os.WriteFile(filepath.Join(parent, "claymod.project.yaml"), []byte(project), 0o644); err != nil {
		t.Fatal(err)
	}

	// A nested dir (parents created by init) under the existing project.
	sub := filepath.Join(parent, "playbooks", "newthing")
	out, err := runInit(t, sub)
	if err != nil {
		t.Fatalf("init returned error: %v (output: %s)", err, out)
	}
	// No local project file: it would shadow the parent's libraries.
	if _, err := os.Stat(filepath.Join(sub, "claymod.project.yaml")); !os.IsNotExist(err) {
		t.Errorf("init shadowed the parent project file: %v", err)
	}
	if !strings.Contains(out, "using the existing project at") {
		t.Errorf("output = %q, want a using-existing-project note", out)
	}
	// The parent's project file is untouched.
	data, err := os.ReadFile(filepath.Join(parent, "claymod.project.yaml"))
	if err != nil || string(data) != project {
		t.Errorf("parent project file changed: %q, err %v", data, err)
	}
}

func TestPlaybookInitKeepsExistingProjectFile(t *testing.T) {
	t.Setenv("CLAYMOD_SCHEMA_DIR", "")
	dir := t.TempDir()
	project := "version: 1\nschemaPaths: [\"./custom\"]\n"
	if err := os.WriteFile(filepath.Join(dir, "claymod.project.yaml"), []byte(project), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := runInit(t, dir)
	if err != nil {
		t.Fatalf("init returned error: %v (output: %s)", err, out)
	}
	data, err := os.ReadFile(filepath.Join(dir, "claymod.project.yaml"))
	if err != nil || string(data) != project {
		t.Errorf("existing project file changed: %q, err %v", data, err)
	}
}
