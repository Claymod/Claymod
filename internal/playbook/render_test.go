package playbook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderTemplateString(t *testing.T) {
	ctx := RenderContext{
		Host: "web01",
		Vars: map[string]string{"port": "8080", "environment": "prod"},
	}
	out, err := RenderTemplateString("host={{.Host}} port={{.Vars.port}} env={{.Vars.environment}}", ctx)
	if err != nil {
		t.Fatalf("RenderTemplateString returned error: %v", err)
	}
	if out != "host=web01 port=8080 env=prod" {
		t.Errorf("rendered = %q", out)
	}
}

func TestRenderTemplateMissingVarFails(t *testing.T) {
	_, err := RenderTemplateString("{{.Vars.nope}}", RenderContext{Vars: map[string]string{}})
	if err == nil {
		t.Fatal("template with missing var rendered successfully")
	}
	if !strings.Contains(err.Error(), "execute template") {
		t.Errorf("error = %q, want execute template failure", err.Error())
	}
}

func TestRenderTemplateFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "conf.tmpl")
	if err := os.WriteFile(path, []byte("hello {{.Host}}"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := RenderTemplate(path, RenderContext{Host: "db01"})
	if err != nil {
		t.Fatalf("RenderTemplate returned error: %v", err)
	}
	if out != "hello db01" {
		t.Errorf("rendered = %q", out)
	}
}

func TestRenderTemplateMissingFile(t *testing.T) {
	if _, err := RenderTemplate("/nope/missing.tmpl", RenderContext{}); err == nil {
		t.Fatal("RenderTemplate accepted a missing file")
	}
}

func TestMergedVars(t *testing.T) {
	merged := MergedVars(
		map[string]string{"a": "1", "b": "2"},
		map[string]string{"b": "override", "c": "3"},
	)
	if merged["a"] != "1" || merged["b"] != "override" || merged["c"] != "3" {
		t.Errorf("merged = %v", merged)
	}
}

func TestResolveSource(t *testing.T) {
	if got := ResolveSource("/playbooks", "files/a.txt"); got != "/playbooks/files/a.txt" {
		t.Errorf("ResolveSource relative = %q", got)
	}
	if got := ResolveSource("/playbooks", "/etc/a.txt"); got != "/etc/a.txt" {
		t.Errorf("ResolveSource absolute = %q", got)
	}
}

func TestValidatePath(t *testing.T) {
	if err := ValidatePath("/etc/hosts"); err != nil {
		t.Errorf("ValidatePath rejected absolute path: %v", err)
	}
	if err := ValidatePath("relative/path"); err == nil {
		t.Error("ValidatePath accepted a relative path")
	}
}

func TestValidateHosts(t *testing.T) {
	available := []string{"web01", "web02", "db01"}

	matched, err := ValidateHosts(nil, available)
	if err != nil || len(matched) != 3 {
		t.Errorf("ValidateHosts(nil) = %v, %v", matched, err)
	}

	matched, err = ValidateHosts([]string{"web01", "db01"}, available)
	if err != nil {
		t.Fatalf("ValidateHosts returned error: %v", err)
	}
	if len(matched) != 2 {
		t.Errorf("matched = %v", matched)
	}

	if _, err := ValidateHosts([]string{"ghost"}, available); err == nil {
		t.Error("ValidateHosts accepted an unknown host")
	} else if !strings.Contains(err.Error(), "ghost") {
		t.Errorf("error = %q, want ghost named", err.Error())
	}
}
