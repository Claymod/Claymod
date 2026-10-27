package modules_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/claymod/claymod/internal/modules"
	_ "github.com/claymod/claymod/internal/modules/all"
	"github.com/claymod/claymod/internal/playbook"
	"github.com/claymod/claymod/internal/proto"
)

// resource builds a playbook.Resource from raw JSON (as PKL eval emits).
func resource(t *testing.T, doc string) playbook.Resource {
	t.Helper()
	var r playbook.Resource
	if err := json.Unmarshal([]byte(doc), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// mustJSON renders v as compact JSON for golden comparison.
func mustJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestCompileCopyGolden(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "motd.txt")
	if err := os.WriteFile(src, []byte("welcome\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := playbook.RenderContext{PlaybookDir: dir, Vars: map[string]string{}}
	res := resource(t, `{
		"type": "std.files.Copy",
		"name": "motd",
		"dependsOn": [],
		"source": "motd.txt",
		"dest": "/etc/motd",
		"mode": "0644",
		"owner": "root",
		"group": "root",
		"backup": true
	}`)

	ops, err := modules.Compile(res, ctx)
	if err != nil {
		t.Fatalf("Compile returned error: %v", err)
	}
	want := `[{"op_type":"file","file":{"path":"/etc/motd","content":"welcome\n","mode":"0644","owner":"root","group":"root","ensure":"file","backup":true}}]`
	if got := mustJSON(t, ops); got != want {
		t.Errorf("ops mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestCompileTemplateGolden(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "app.tmpl")
	if err := os.WriteFile(src, []byte("host={{.Host}} port={{.Vars.port}}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := playbook.RenderContext{
		Host:        "web01",
		PlaybookDir: dir,
		Vars:        map[string]string{"port": "8080", "env": "prod"},
	}
	res := resource(t, `{
		"type": "std.files.Template",
		"name": "app.conf",
		"dependsOn": [],
		"source": "app.tmpl",
		"dest": "/etc/app.conf",
		"mode": "0640",
		"vars": {"port": "9090"},
		"owner": "",
		"group": "",
		"backup": false
	}`)

	ops, err := modules.Compile(res, ctx)
	if err != nil {
		t.Fatalf("Compile returned error: %v", err)
	}
	// Resource vars override playbook vars (port 9090, not 8080).
	// Wire shape uses omitempty: absent fields decode as zero values.
	want := `[{"op_type":"file","file":{"path":"/etc/app.conf","content":"host=web01 port=9090\n","mode":"0640","ensure":"file"}}]`
	if got := mustJSON(t, ops); got != want {
		t.Errorf("ops mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestCompileDirectoryGolden(t *testing.T) {
	ctx := playbook.RenderContext{Vars: map[string]string{}}
	res := resource(t, `{
		"type": "std.files.Directory",
		"name": "logdir",
		"dependsOn": [],
		"path": "/var/log/app",
		"mode": "0750",
		"ensure": "directory",
		"owner": "",
		"group": ""
	}`)

	ops, err := modules.Compile(res, ctx)
	if err != nil {
		t.Fatalf("Compile returned error: %v", err)
	}
	want := `[{"op_type":"file","file":{"path":"/var/log/app","mode":"0750","ensure":"directory"}}]`
	if got := mustJSON(t, ops); got != want {
		t.Errorf("ops mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestCompileShellGolden(t *testing.T) {
	ctx := playbook.RenderContext{Vars: map[string]string{}}
	res := resource(t, `{
		"type": "std.commands.Shell",
		"name": "reload",
		"dependsOn": [],
		"command": "systemctl daemon-reload",
		"argv": [],
		"cwd": "/opt/app",
		"env": {"FOO": "bar"},
		"onlyIf": "test -f /etc/app.conf",
		"unlessIf": "",
		"creates": "",
		"removes": "",
		"timeout": 5000
	}`)

	ops, err := modules.Compile(res, ctx)
	if err != nil {
		t.Fatalf("Compile returned error: %v", err)
	}
	want := `[{"op_type":"command","command":{"shell":"systemctl daemon-reload","cwd":"/opt/app","env":{"FOO":"bar"},"only_if":"test -f /etc/app.conf","timeout_ms":5000}}]`
	if got := mustJSON(t, ops); got != want {
		t.Errorf("ops mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestCompileScriptGolden(t *testing.T) {
	ctx := playbook.RenderContext{Host: "web01", Vars: map[string]string{"who": "world"}}
	res := resource(t, `{
		"type": "std.commands.Script",
		"name": "setup",
		"dependsOn": [],
		"content": "echo hello {{.Vars.who}}",
		"path": "/tmp/setup.sh",
		"mode": "0755",
		"cwd": "",
		"env": {},
		"onlyIf": "",
		"unlessIf": "",
		"timeout": 0
	}`)

	ops, err := modules.Compile(res, ctx)
	if err != nil {
		t.Fatalf("Compile returned error: %v", err)
	}
	// Script = File op (write) + Command op (run).
	want := `[` +
		`{"op_type":"file","file":{"path":"/tmp/setup.sh","content":"echo hello world","mode":"0755","ensure":"file"}},` +
		`{"op_type":"command","command":{"argv":["/tmp/setup.sh"]}}` +
		`]`
	if got := mustJSON(t, ops); got != want {
		t.Errorf("ops mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestCompileUnitGolden(t *testing.T) {
	ctx := playbook.RenderContext{Vars: map[string]string{}}
	res := resource(t, `{
		"type": "std.service.Unit",
		"name": "nginx",
		"dependsOn": [],
		"unit": "nginx",
		"state": "started",
		"enabled": true
	}`)

	ops, err := modules.Compile(res, ctx)
	if err != nil {
		t.Fatalf("Compile returned error: %v", err)
	}
	want := `[{"op_type":"service","service":{"unit":"nginx","state":"started","enabled":true}}]`
	if got := mustJSON(t, ops); got != want {
		t.Errorf("ops mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestCompileUnitEnabledNull(t *testing.T) {
	ctx := playbook.RenderContext{Vars: map[string]string{}}
	res := resource(t, `{
		"type": "std.service.Unit",
		"name": "nginx",
		"dependsOn": [],
		"unit": "nginx.service",
		"state": "stopped",
		"enabled": null
	}`)

	ops, err := modules.Compile(res, ctx)
	if err != nil {
		t.Fatalf("Compile returned error: %v", err)
	}
	// `enabled: null` decodes to a nil pointer; the wire shape omits it.
	want := `[{"op_type":"service","service":{"unit":"nginx.service","state":"stopped"}}]`
	if got := mustJSON(t, ops); got != want {
		t.Errorf("ops mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestCompileAllInPlanOrder(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "motd.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	doc := `{
		"hosts": ["web01"],
		"vars": {"greeting": "hello"},
		"resources": [
			{"type": "std.service.Unit", "name": "svc", "dependsOn": ["motd"], "unit": "nginx", "state": "started", "enabled": true},
			{"type": "std.files.Copy", "name": "motd", "dependsOn": [], "source": "motd.txt", "dest": "/etc/motd", "mode": "0644", "owner": "", "group": "", "backup": false}
		]
	}`
	pb, err := playbook.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := pb.Plan("web01")
	if err != nil {
		t.Fatal(err)
	}
	ops, err := modules.CompileAll(pb, plan, playbook.RenderContext{Host: "web01", PlaybookDir: dir, Vars: pb.Vars})
	if err != nil {
		t.Fatalf("CompileAll returned error: %v", err)
	}
	if len(ops) != 2 {
		t.Fatalf("got %d ops, want 2", len(ops))
	}
	// Topological order: motd (File) before svc (Service), even though
	// svc was declared first.
	if ops[0].OpType != proto.OpTypeFile || ops[1].OpType != proto.OpTypeService {
		t.Errorf("op order = %s, %s; want file, service", ops[0].OpType, ops[1].OpType)
	}
}

func TestCompileErrors(t *testing.T) {
	ctx := playbook.RenderContext{PlaybookDir: t.TempDir(), Vars: map[string]string{}}
	cases := []struct {
		name string
		doc  string
		want string
	}{
		{
			name: "unknown type",
			doc:  `{"type": "std.bogus.Thing", "name": "x"}`,
			want: "no compiler registered",
		},
		{
			name: "copy missing source",
			doc:  `{"type": "std.files.Copy", "name": "x", "source": "", "dest": "/a"}`,
			want: "source is required",
		},
		{
			name: "copy relative dest",
			doc:  `{"type": "std.files.Copy", "name": "x", "source": "a", "dest": "relative/a"}`,
			want: "absolute",
		},
		{
			name: "copy missing source file",
			doc:  `{"type": "std.files.Copy", "name": "x", "source": "ghost.txt", "dest": "/a"}`,
			want: "read source",
		},
		{
			name: "template missing dest",
			doc:  `{"type": "std.files.Template", "name": "x", "source": "a", "dest": ""}`,
			want: "dest is required",
		},
		{
			name: "directory bad ensure",
			doc:  `{"type": "std.files.Directory", "name": "x", "path": "/a", "ensure": "wonky"}`,
			want: "invalid ensure",
		},
		{
			name: "shell both command and argv",
			doc:  `{"type": "std.commands.Shell", "name": "x", "command": "true", "argv": ["true"]}`,
			want: "exactly one of command or argv",
		},
		{
			name: "shell neither command nor argv",
			doc:  `{"type": "std.commands.Shell", "name": "x", "command": "", "argv": []}`,
			want: "exactly one of command or argv",
		},
		{
			name: "script missing path",
			doc:  `{"type": "std.commands.Script", "name": "x", "content": "true", "path": ""}`,
			want: "path is required",
		},
		{
			name: "unit missing unit",
			doc:  `{"type": "std.service.Unit", "name": "x", "unit": "", "state": "started"}`,
			want: "unit is required",
		},
		{
			name: "unit bad state",
			doc:  `{"type": "std.service.Unit", "name": "x", "unit": "nginx", "state": "wonky"}`,
			want: "invalid state",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := modules.Compile(resource(t, tc.doc), ctx)
			if err == nil {
				t.Fatalf("Compile accepted bad resource: %s", tc.doc)
			}
			want := tc.want
			got := err.Error()
			if !strings.Contains(got, want) {
				t.Errorf("error = %q, want substring %q", got, want)
			}
		})
	}
}

func TestRegisterDuplicatePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("duplicate registration did not panic")
		}
	}()
	modules.Register("std.files.Copy", modules.CompilerFunc(
		func(playbook.Resource, playbook.RenderContext) ([]proto.Op, error) { return nil, nil }))
}
