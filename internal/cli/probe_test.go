package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/claymod/claymod/internal/agent"
	"github.com/claymod/claymod/internal/ca"
	"github.com/claymod/claymod/internal/proto"
)

// probeTestSetup creates a CA, an agent identity, a probe identity and
// starts a real agent on a loopback port. It returns the address and the
// paths to the CA and probe cert/key.
type probeTestSetup struct {
	addr      string
	caFile    string
	certFile  string
	keyFile   string
	ca        *ca.CA
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	agentName string
}

func newProbeTestSetup(t *testing.T) *probeTestSetup {
	t.Helper()
	authority, err := ca.New("probe-test-ca")
	if err != nil {
		t.Fatal(err)
	}
	agentPEM, agentKey, err := authority.IssueCert(ca.IssueOptions{
		CommonName: "agent.sim",
		Usage:      ca.UsageServer,
		DNSNames:   []string{"localhost", "agent.sim"},
	})
	if err != nil {
		t.Fatal(err)
	}
	probePEM, probeKey, err := authority.IssueCert(ca.IssueOptions{
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
	s := &probeTestSetup{addr: ln.Addr().String(), ca: authority, cancel: cancel, agentName: "agent.sim"}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		_ = a.Serve(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		s.wg.Wait()
	})

	dir := t.TempDir()
	s.caFile = filepath.Join(dir, "ca.pem")
	s.certFile = filepath.Join(dir, "probe.pem")
	s.keyFile = filepath.Join(dir, "probe-key.pem")
	writeTestFile(t, s.caFile, authority.CertPEM())
	writeTestFile(t, s.certFile, probePEM)
	writeTestFile(t, s.keyFile, probeKey)
	return s
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestProbeSuccess(t *testing.T) {
	s := newProbeTestSetup(t)
	smokePath := filepath.Join(t.TempDir(), "smoke.txt")
	out := new(bytes.Buffer)
	err := runProbe(context.Background(), out, probeOptions{
		addr:       s.addr,
		serverName: "localhost",
		caFile:     s.caFile,
		certFile:   s.certFile,
		keyFile:    s.keyFile,
		smokePath:  smokePath,
	})
	if err != nil {
		t.Fatalf("runProbe returned error: %v\noutput:\n%s", err, out.String())
	}
	log := out.String()
	for _, want := range []string{"TLS handshake OK", "Ping OK", "Facts OK", "Apply smoke OK", "PROBE OK"} {
		if !strings.Contains(log, want) {
			t.Errorf("probe output missing %q:\n%s", want, log)
		}
	}
}

func TestProbeExpectRejectWithUntrustedCert(t *testing.T) {
	s := newProbeTestSetup(t)

	// A client cert from a different CA must be refused.
	rogue, err := ca.New("rogue-ca")
	if err != nil {
		t.Fatal(err)
	}
	roguePEM, rogueKey, err := rogue.IssueCert(ca.IssueOptions{
		CommonName: "control.sim", Usage: ca.UsageClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rogueCert := filepath.Join(dir, "rogue.pem")
	rogueKeyPath := filepath.Join(dir, "rogue-key.pem")
	writeTestFile(t, rogueCert, roguePEM)
	writeTestFile(t, rogueKeyPath, rogueKey)

	out := new(bytes.Buffer)
	err = runProbe(context.Background(), out, probeOptions{
		addr:         s.addr,
		serverName:   "localhost",
		caFile:       s.caFile,
		certFile:     rogueCert,
		keyFile:      rogueKeyPath,
		expectReject: true,
	})
	if err != nil {
		t.Fatalf("runProbe(expect-reject) returned error: %v\noutput:\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "REJECTED as expected") {
		t.Errorf("output missing rejection marker:\n%s", out.String())
	}
}

func TestProbeRejectsUntrustedServer(t *testing.T) {
	s := newProbeTestSetup(t)

	// The probe verifies the server against its own CA file: a CA file
	// from another authority must fail the TLS handshake.
	rogue, err := ca.New("rogue-ca")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	wrongCA := filepath.Join(dir, "wrong-ca.pem")
	writeTestFile(t, wrongCA, rogue.CertPEM())

	out := new(bytes.Buffer)
	err = runProbe(context.Background(), out, probeOptions{
		addr:         s.addr,
		serverName:   "localhost",
		caFile:       wrongCA,
		certFile:     s.certFile,
		keyFile:      s.keyFile,
		expectReject: true,
	})
	if err != nil {
		t.Fatalf("runProbe(expect-reject) returned error: %v\noutput:\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "REJECTED as expected") {
		t.Errorf("output missing rejection marker:\n%s", out.String())
	}
}

func TestProbeExpectRejectFailsWhenConnected(t *testing.T) {
	s := newProbeTestSetup(t)
	out := new(bytes.Buffer)
	err := runProbe(context.Background(), out, probeOptions{
		addr:         s.addr,
		serverName:   "localhost",
		caFile:       s.caFile,
		certFile:     s.certFile,
		keyFile:      s.keyFile,
		expectReject: true,
	})
	if err == nil {
		t.Fatal("expect-reject accepted a successful connection")
	}
}

func TestHostOfAddr(t *testing.T) {
	if got := hostOfAddr("agent.sim:2323"); got != "agent.sim" {
		t.Errorf("hostOfAddr = %q, want agent.sim", got)
	}
	if got := hostOfAddr("127.0.0.1:2323"); got != "127.0.0.1" {
		t.Errorf("hostOfAddr = %q, want 127.0.0.1", got)
	}
}
