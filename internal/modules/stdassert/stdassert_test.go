package stdassert

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/claymod/claymod/internal/modules"
	"github.com/claymod/claymod/internal/playbook"
	"github.com/claymod/claymod/internal/proto"
)

// runShell executes shell under /bin/sh, returning the exit code.
func runShell(t *testing.T, shellText string) int {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", shellText)
	code := 0
	if err := cmd.Run(); err != nil {
		code = cmd.ProcessState.ExitCode()
	}
	return code
}

func lookPath(bin string) (string, error) { return exec.LookPath(bin) }

// compile parses doc (as PKL eval would emit it) and returns the
// resource's single compiled op, dispatched through the shared
// registry (this package's init populates it).
func compile(t *testing.T, doc string) *proto.CommandOp {
	t.Helper()
	var res playbook.Resource
	if err := json.Unmarshal([]byte(doc), &res); err != nil {
		t.Fatal(err)
	}
	ops, err := modules.Compile(res, playbook.RenderContext{Vars: map[string]string{}})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return ops[0].Command
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

func TestCommandGolden(t *testing.T) {
	cmd := compile(t, `{"type":"std.assert.Command","name":"x","command":"test -f /etc/hostname","timeout":5000}`)
	if cmd.Shell != "test -f /etc/hostname" || cmd.Timeout != 5000 || cmd.UnlessIf != "" || cmd.OnlyIf != "" {
		t.Errorf("op = %+v", cmd)
	}
}

func TestFileContainsGolden(t *testing.T) {
	cmd := compile(t, `{"type":"std.assert.FileContains","name":"x","path":"/etc/motd","pattern":"claymod"}`)
	want := `grep -qF -- 'claymod' '/etc/motd'`
	if cmd.Shell != want {
		t.Errorf("shell = %q, want %q", cmd.Shell, want)
	}
}

func TestPortListeningGolden(t *testing.T) {
	cmd := compile(t, `{"type":"std.assert.PortListening","name":"x","port":8080}`)
	for _, want := range []string{
		"command -v ss",
		"awk -v p='8080'",
		`$0 ~ "[:.]"p"( |$)"`,
		"command -v netstat",
		"exit 1",
	} {
		if !strings.Contains(cmd.Shell, want) {
			t.Errorf("shell = %q, want it to contain %q", cmd.Shell, want)
		}
	}
}

func TestAssertCommandBehavior(t *testing.T) {
	pass := compile(t, `{"type":"std.assert.Command","name":"x","command":"true"}`)
	fail := compile(t, `{"type":"std.assert.Command","name":"x","command":"false"}`)
	if code := runShell(t, pass.Shell); code != 0 {
		t.Errorf("assertion command exited %d, want 0", code)
	}
	if code := runShell(t, fail.Shell); code == 0 {
		t.Error("failing assertion exited 0")
	}
}

func TestFileContainsBehavior(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "conf")
	if err := os.WriteFile(path, []byte("listen 8080\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hit := compile(t, `{"type":"std.assert.FileContains","name":"x","path":"`+path+`","pattern":"listen 8080"}`)
	miss := compile(t, `{"type":"std.assert.FileContains","name":"x","path":"`+path+`","pattern":"listen 9090"}`)
	ghost := compile(t, `{"type":"std.assert.FileContains","name":"x","path":"`+filepath.Join(dir, "ghost")+`","pattern":"x"}`)
	if code := runShell(t, hit.Shell); code != 0 {
		t.Errorf("contains-assert exited %d, want 0", code)
	}
	if code := runShell(t, miss.Shell); code == 0 {
		t.Error("missing-pattern assertion exited 0")
	}
	if code := runShell(t, ghost.Shell); code == 0 {
		t.Error("missing-file assertion exited 0")
	}
}

// TestPortListeningBehavior uses a REAL listener: while it is up the
// assertion passes (via netstat on macOS, ss on Linux CI), after it is
// closed the assertion fails.
func TestPortListeningBehavior(t *testing.T) {
	if _, err := lookPath("netstat"); err != nil {
		if _, err := lookPath("ss"); err != nil {
			t.Skip("neither netstat nor ss available")
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	up := compile(t, `{"type":"std.assert.PortListening","name":"x","port":`+itoa(port)+`}`)
	if code := runShell(t, up.Shell); code != 0 {
		t.Errorf("listening assert exited %d, want 0", code)
	}

	// A closed port must fail — including the similar-looking port
	// above/below it (the regex anchors the whole address component).
	if code := runShell(t, compile(t, `{"type":"std.assert.PortListening","name":"x","port":1}`).Shell); code == 0 {
		t.Error("port 1 assertion exited 0 — is something listening on port 1?")
	}
	ln.Close()
	if code := runShell(t, up.Shell); code == 0 {
		t.Error("closed-port assertion exited 0")
	}
}
