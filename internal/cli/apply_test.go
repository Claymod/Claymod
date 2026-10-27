package cli

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/claymod/claymod/internal/agent"
	"github.com/claymod/claymod/internal/ca"
	"github.com/claymod/claymod/internal/inventory"
	"github.com/claymod/claymod/internal/proto"
)

// startLoopbackAgent starts an agent on 127.0.0.1:<port> and returns the
// port plus paths to the control identity (for the apply CLI).
func startLoopbackAgent(t *testing.T, agentCN string) (port int, caFile, certFile, keyFile string) {
	t.Helper()
	authority, err := ca.New("apply-e2e-ca")
	if err != nil {
		t.Fatal(err)
	}
	agentPEM, agentKey, err := authority.IssueCert(ca.IssueOptions{
		CommonName: agentCN,
		Usage:      ca.UsageServer,
		DNSNames:   []string{agentCN, "localhost"},
	})
	if err != nil {
		t.Fatal(err)
	}
	controlPEM, controlKey, err := authority.IssueCert(ca.IssueOptions{
		CommonName: "control.sim",
		Usage:      ca.UsageClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	agentID, err := proto.LoadIdentity(agentPEM, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := authority.Pool()
	ln, err := proto.Listen("127.0.0.1:0", agentID, pool)
	if err != nil {
		t.Fatal(err)
	}
	a := agent.New(agent.Options{})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = a.Serve(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		ln.Close()
	})

	dir := t.TempDir()
	caFile = filepath.Join(dir, "ca.pem")
	certFile = filepath.Join(dir, "control.pem")
	keyFile = filepath.Join(dir, "control-key.pem")
	writeFile(t, caFile, authority.CertPEM())
	writeFile(t, certFile, controlPEM)
	writeFile(t, keyFile, controlKey)

	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener addr is %T", ln.Addr())
	}
	return tcpAddr.Port, caFile, certFile, keyFile
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeE2EPlaybook writes a 3-resource playbook (Copy, Template, guarded
// Shell) targeting hostname into a temp dir, and returns the playbook path
// and the marker path the shell command creates.
func writeE2EPlaybook(t *testing.T, hostname, marker string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "files"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "files", "motd.txt"), []byte("managed by claymod\n"))
	playbook := fmt.Sprintf(`amends "modulepath:/claymod/base.pkl"
import "modulepath:/claymod/std/files.pkl"
import "modulepath:/claymod/std/commands.pkl"

hosts {
  "%s"
}

vars {
  ["greeting"] = "hello"
}

resources {
  new files.Copy {
    name = "motd"
    source = "files/motd.txt"
    dest = "%s"
    mode = "0644"
  }
  new files.Template {
    name = "conf"
    source = "files/conf.tmpl"
    dest = "%s"
    mode = "0644"
  }
  new commands.Shell {
    name = "marker"
    command = "touch %s"
    creates = "%s"
  }
}
`, hostname,
		filepath.Join(dir, "motd-out.txt"),
		filepath.Join(dir, "conf-out.txt"),
		marker, marker)
	writeFile(t, filepath.Join(dir, "playbook.pkl"), []byte(playbook))
	writeFile(t, filepath.Join(dir, "files", "conf.tmpl"),
		[]byte("host={{.Host}} greeting={{.Vars.greeting}}\n"))
	return filepath.Join(dir, "playbook.pkl")
}

// runApplyCLI drives `claymod playbook apply` and returns its output.
func runApplyCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	out := new(bytes.Buffer)
	cmd := newRootCmd()
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs(append([]string{"playbook", "apply"}, args...))
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

// TestPlaybookApplyE2E is the Phase 6 acceptance: real PKL playbook,
// sqlite inventory, loopback agent over mTLS, results and idempotent
// re-run.
func TestPlaybookApplyE2E(t *testing.T) {
	requirePklCLI(t)
	t.Setenv("CLAYMOD_SCHEMA_DIR", testSchemaDir(t))

	hostname := "web01"
	port, caFile, certFile, keyFile := startLoopbackAgent(t, hostname)
	marker := filepath.Join(t.TempDir(), "marker.txt")
	playbookFile := writeE2EPlaybook(t, hostname, marker)

	// Fake inventory: one host at 127.0.0.1.
	invPath := filepath.Join(t.TempDir(), "inventory.db")
	inv, err := inventory.Open(invPath, "127.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	if err := inv.AddHost(&inventory.Host{Hostname: hostname, WGIP: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if err := inv.Close(); err != nil {
		t.Fatal(err)
	}

	applyArgs := func(extra ...string) []string {
		base := []string{
			"--inventory", invPath,
			"--agent-network", "127.0.0.0/8",
			"--agent-port", fmt.Sprintf("%d", port),
			"--ca", caFile,
			"--cert", certFile,
			"--key", keyFile,
		}
		return append(base, extra...)
	}

	// First apply: all three resources change.
	out, err := runApplyCLI(t, append(applyArgs(), playbookFile)...)
	if err != nil {
		t.Fatalf("apply returned error: %v\noutput:\n%s", err, out)
	}
	for _, want := range []string{
		"applying 3 resource op(s) to 1 host(s)",
		"changed",
		"3 ok, 3 changed, 0 failed",
		"apply complete",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("first apply output missing %q:\n%s", want, out)
		}
	}

	// Effects landed on the host.
	if data, err := os.ReadFile(filepath.Join(filepath.Dir(playbookFile), "motd-out.txt")); err != nil {
		t.Fatalf("copy dest missing: %v", err)
	} else if !strings.Contains(string(data), "managed by claymod") {
		t.Errorf("copy dest content = %q", data)
	}
	confData, err := os.ReadFile(filepath.Join(filepath.Dir(playbookFile), "conf-out.txt"))
	if err != nil {
		t.Fatalf("template dest missing: %v", err)
	}
	if want := fmt.Sprintf("host=%s greeting=hello", hostname); !strings.Contains(string(confData), want) {
		t.Errorf("template content = %q, want %q", confData, want)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("guarded shell did not create the marker: %v", err)
	}

	// Second apply: idempotent — nothing changes (guard skips the shell).
	out, err = runApplyCLI(t, append(applyArgs(), playbookFile)...)
	if err != nil {
		t.Fatalf("re-apply returned error: %v\noutput:\n%s", err, out)
	}
	if want := "3 ok, 0 changed, 0 failed"; !strings.Contains(out, want) {
		t.Errorf("re-apply not idempotent, missing %q:\n%s", want, out)
	}
}

// TestPlaybookApplyCheckMode verifies --check reports would-change and
// leaves the host untouched.
func TestPlaybookApplyCheckMode(t *testing.T) {
	requirePklCLI(t)
	t.Setenv("CLAYMOD_SCHEMA_DIR", testSchemaDir(t))

	hostname := "web01"
	port, caFile, certFile, keyFile := startLoopbackAgent(t, hostname)
	marker := filepath.Join(t.TempDir(), "marker.txt")
	playbookFile := writeE2EPlaybook(t, hostname, marker)

	invPath := filepath.Join(t.TempDir(), "inventory.db")
	inv, err := inventory.Open(invPath, "127.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	if err := inv.AddHost(&inventory.Host{Hostname: hostname, WGIP: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	inv.Close()

	out, err := runApplyCLI(t,
		"--inventory", invPath,
		"--agent-network", "127.0.0.0/8",
		"--agent-port", fmt.Sprintf("%d", port),
		"--ca", caFile,
		"--cert", certFile,
		"--key", keyFile,
		"--check", playbookFile)
	if err != nil {
		t.Fatalf("check apply returned error: %v\noutput:\n%s", err, out)
	}
	if want := "check complete (nothing was changed)"; !strings.Contains(out, want) {
		t.Errorf("check output missing %q:\n%s", want, out)
	}
	if want := "3 ok, 3 changed, 0 failed"; !strings.Contains(out, want) {
		t.Errorf("check output missing would-change totals %q:\n%s", want, out)
	}
	// Nothing may be created in check mode.
	if _, err := os.Stat(filepath.Join(filepath.Dir(playbookFile), "motd-out.txt")); !os.IsNotExist(err) {
		t.Error("check mode created the copy destination")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Error("check mode created the shell marker")
	}
}

// TestPlaybookApplyLimit verifies --limit narrows the host selection.
func TestPlaybookApplyLimit(t *testing.T) {
	requirePklCLI(t)
	t.Setenv("CLAYMOD_SCHEMA_DIR", testSchemaDir(t))

	hostname := "web01"
	port, caFile, certFile, keyFile := startLoopbackAgent(t, hostname)
	marker := filepath.Join(t.TempDir(), "marker.txt")
	playbookFile := writeE2EPlaybook(t, hostname, marker)

	invPath := filepath.Join(t.TempDir(), "inventory.db")
	inv, err := inventory.Open(invPath, "127.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	if err := inv.AddHost(&inventory.Host{Hostname: hostname, WGIP: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	inv.Close()

	// --limit naming an untargeted host must fail.
	out, err := runApplyCLI(t,
		"--inventory", invPath,
		"--agent-network", "127.0.0.0/8",
		"--agent-port", fmt.Sprintf("%d", port),
		"--ca", caFile,
		"--cert", certFile,
		"--key", keyFile,
		"--limit", "ghost-host", playbookFile)
	if err == nil {
		t.Fatalf("apply with bad --limit succeeded:\n%s", out)
	}
	if !strings.Contains(err.Error(), "ghost-host") {
		t.Errorf("error = %q, want ghost-host named", err.Error())
	}

	// --limit naming the targeted host succeeds.
	out, err = runApplyCLI(t,
		"--inventory", invPath,
		"--agent-network", "127.0.0.0/8",
		"--agent-port", fmt.Sprintf("%d", port),
		"--ca", caFile,
		"--cert", certFile,
		"--key", keyFile,
		"--limit", hostname, playbookFile)
	if err != nil {
		t.Fatalf("apply with --limit returned error: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "apply complete") {
		t.Errorf("output = %q", out)
	}
}
