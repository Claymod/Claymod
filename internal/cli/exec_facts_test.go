package cli

import (
	"bytes"
	"context"
	"errors"
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
	"github.com/claymod/claymod/internal/state"
)

// Phase 8 command tests: exec, host facts and the apply output polish.
// The setup mirrors `claymod serve` + a real enrolled host: the state
// owns the CA, and the loopback agent's certificate is issued by THAT
// CA (a throwaway CA would make the mTLS handshake fail for real).

// startAgentWithCA starts a loopback agent whose certificate is issued
// by the given CA (as enrollment does) and returns its port.
func startAgentWithCA(t *testing.T, authority *ca.CA, agentCN string) int {
	t.Helper()
	agentPEM, agentKey, err := authority.IssueCert(ca.IssueOptions{
		CommonName: agentCN,
		Usage:      ca.UsageServer,
		DNSNames:   []string{agentCN, "localhost"},
	})
	if err != nil {
		t.Fatal(err)
	}
	agentID, err := proto.LoadIdentity(agentPEM, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	// 127.0.0.2: first host address in a 127.0.0.0/8 overlay (127.0.0.1
	// is reserved for the control server — IPAM, 2026-10-27).
	ln, err := proto.Listen("127.0.0.1:0", agentID, authority.Pool())
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
	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener addr is %T", ln.Addr())
	}
	return tcpAddr.Port
}

// startTestSystem brings up state + inventory + a loopback agent under
// the state's CA and returns the data dir, inventory path and port.
func startTestSystem(t *testing.T, hostname string) (dataDir, invPath string, port int) {
	t.Helper()
	dataDir = t.TempDir()
	st, err := state.Open(dataDir, "claymod.internal")
	if err != nil {
		t.Fatal(err)
	}
	port = startAgentWithCA(t, st.CA, hostname)

	invPath = filepath.Join(dataDir, "inventory.db")
	inv := openInventoryForTest(t, invPath)
	addHostForTest(t, inv, hostname, "127.0.0.1")
	return dataDir, invPath, port
}

func openInventoryForTest(t *testing.T, invPath string) *inventory.Inventory {
	t.Helper()
	inv, err := inventory.Open(invPath, "127.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { inv.Close() })
	return inv
}

func addHostForTest(t *testing.T, inv *inventory.Inventory, hostname, ip string) {
	t.Helper()
	if err := inv.AddHost(&inventory.Host{Hostname: hostname, WGIP: ip}); err != nil {
		t.Fatal(err)
	}
}

func TestExecRunsRemoteCommand(t *testing.T) {
	hostname := "web01"
	dataDir, _, port := startTestSystem(t, hostname)

	out := new(bytes.Buffer)
	cmd := newRootCmd()
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{
		"exec", "--host", hostname,
		"--data-dir", dataDir,
		"--agent-port", fmt.Sprintf("%d", port),
		"--shell", "echo hello-from-remote",
	})
	err := cmd.ExecuteContext(context.Background())
	if err != nil {
		t.Fatalf("exec returned error: %v\noutput:\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "hello-from-remote") {
		t.Errorf("output missing remote stdout:\n%s", out.String())
	}
}

func TestExecPropagatesExitCode(t *testing.T) {
	hostname := "web01"
	dataDir, _, port := startTestSystem(t, hostname)

	out := new(bytes.Buffer)
	cmd := newRootCmd()
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{
		"exec", "--host", hostname,
		"--data-dir", dataDir,
		"--agent-port", fmt.Sprintf("%d", port),
		"--shell", "exit 3",
	})
	err := cmd.ExecuteContext(context.Background())
	if err == nil {
		t.Fatal("exec with exit 3 returned nil")
	}
	var exitErr ExitCoder
	if !errors.As(err, &exitErr) {
		t.Fatalf("error is not an ExitCoder: %v", err)
	}
	if exitErr.ExitCode() != 3 {
		t.Errorf("exit code = %d, want 3", exitErr.ExitCode())
	}
}

func TestExecArgvForm(t *testing.T) {
	hostname := "web01"
	dataDir, _, port := startTestSystem(t, hostname)

	out := new(bytes.Buffer)
	cmd := newRootCmd()
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{
		"exec", "--host", hostname,
		"--data-dir", dataDir,
		"--agent-port", fmt.Sprintf("%d", port),
		"--", "/bin/echo", "argv-form",
	})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("exec argv returned error: %v\noutput:\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "argv-form") {
		t.Errorf("output = %q", out.String())
	}
}

func TestExecRejectsMissingHost(t *testing.T) {
	out := new(bytes.Buffer)
	cmd := newRootCmd()
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"exec", "--shell", "true"})
	if err := cmd.ExecuteContext(context.Background()); err == nil {
		t.Fatal("exec without --host succeeded")
	}
}

func TestHostFactsLive(t *testing.T) {
	hostname := "web01"
	dataDir, _, port := startTestSystem(t, hostname)

	out := new(bytes.Buffer)
	cmd := newRootCmd()
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{
		"host", "facts", hostname,
		"--data-dir", dataDir,
		"--agent-port", fmt.Sprintf("%d", port),
	})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("host facts returned error: %v\noutput:\n%s", err, out.String())
	}
	log := out.String()
	for _, want := range []string{"(live)", "host=", "os="} {
		if !strings.Contains(log, want) {
			t.Errorf("facts output missing %q:\n%s", want, log)
		}
	}
}

func TestHostFactsCached(t *testing.T) {
	hostname := "web01"
	dataDir, invPath, _ := startTestSystem(t, hostname)

	// Seed the inventory's cached facts directly (what an agent push
	// would store).
	inv := openInventoryForTest(t, invPath)
	host, err := inv.GetHost(hostname)
	if err != nil {
		t.Fatal(err)
	}
	host.Facts = `{"hostname":"web01","os":"linux","arch":"arm64","kernel":"6.1"}`
	if err := inv.UpdateHost(host); err != nil {
		t.Fatal(err)
	}

	out := new(bytes.Buffer)
	cmd := newRootCmd()
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"host", "facts", hostname,
		"--data-dir", dataDir, "--cached"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("host facts --cached returned error: %v\noutput:\n%s", err, out.String())
	}
	log := out.String()
	for _, want := range []string{"(cached)", "os=linux", "arch=arm64"} {
		if !strings.Contains(log, want) {
			t.Errorf("cached facts output missing %q:\n%s", want, log)
		}
	}
}

func TestApplyVerboseOpDetail(t *testing.T) {
	requirePklCLI(t)
	t.Setenv("CLAYMOD_SCHEMA_DIR", testSchemaDir(t))

	hostname := "web01"
	dataDir, invPath, port := startTestSystem(t, hostname)
	marker := filepath.Join(t.TempDir(), "marker.txt")
	playbookFile := writeE2EPlaybook(t, hostname, marker)

	out := new(bytes.Buffer)
	cmd := newRootCmd()
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{
		"playbook", "apply", playbookFile,
		"--data-dir", dataDir,
		"--inventory", invPath,
		"--agent-network", "127.0.0.0/8",
		"--agent-port", fmt.Sprintf("%d", port),
		"--verbose",
	})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("apply --verbose returned error: %v\noutput:\n%s", err, out.String())
	}
	log := out.String()
	// Verbose mode prints one line per op with a change marker.
	if !strings.Contains(log, "+") {
		t.Errorf("verbose output has no op markers:\n%s", log)
	}
	if strings.Count(log, "\n") < 5 {
		t.Errorf("verbose output too short (no op detail):\n%s", log)
	}
}

func TestApplyDataDirDefaults(t *testing.T) {
	requirePklCLI(t)
	t.Setenv("CLAYMOD_SCHEMA_DIR", testSchemaDir(t))

	hostname := "web01"
	dataDir, invPath, port := startTestSystem(t, hostname)
	marker := filepath.Join(t.TempDir(), "marker.txt")
	playbookFile := writeE2EPlaybook(t, hostname, marker)

	// No --ca/--cert/--key: the control identity comes from --data-dir.
	out := new(bytes.Buffer)
	cmd := newRootCmd()
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{
		"playbook", "apply", playbookFile,
		"--data-dir", dataDir,
		"--inventory", invPath,
		"--agent-network", "127.0.0.0/8",
		"--agent-port", fmt.Sprintf("%d", port),
	})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("apply with data-dir defaults returned error: %v\noutput:\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "apply complete") {
		t.Errorf("output = %q", out.String())
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("apply with defaults did not reach the agent: %v", err)
	}
}
