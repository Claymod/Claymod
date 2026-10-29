package runner_test

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/claymod/claymod/internal/agent"
	"github.com/claymod/claymod/internal/ca"
	"github.com/claymod/claymod/internal/proto"
	"github.com/claymod/claymod/internal/runner"
)

// issuedSerials maps agent cert serial -> hostname (revocation tests).
var issuedSerials = map[string]string{}

// testCluster starts n agents on loopback ports and returns their targets
// plus the control-side identity and pool.
type testCluster struct {
	Targets    []runner.Target
	Identity   proto.Identity
	ServerPool *x509.CertPool
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

func startCluster(t *testing.T, n int) *testCluster {
	t.Helper()
	authority, err := ca.New("runner-test-ca")
	if err != nil {
		t.Fatal(err)
	}
	controlPEM, controlKey, err := authority.IssueCert(ca.IssueOptions{
		CommonName: "control.sim", Usage: ca.UsageClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	id, err := proto.LoadIdentity(controlPEM, controlKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := authority.Pool()

	cluster := &testCluster{Identity: id, ServerPool: pool}
	ctx, cancel := context.WithCancel(context.Background())
	cluster.cancel = cancel

	for k := 0; k < n; k++ {
		hostname := "host-" + string(rune('a'+k))
		agentPEM, agentKey, err := authority.IssueCert(ca.IssueOptions{
			CommonName: hostname,
			Usage:      ca.UsageServer,
			DNSNames:   []string{hostname, "localhost"},
		})
		if err != nil {
			t.Fatal(err)
		}
		agentID, err := proto.LoadIdentity(agentPEM, agentKey)
		if err != nil {
			t.Fatal(err)
		}
		// Record the agent's cert serial for the revocation tests.
		if cert, err := ca.ParseCertPEM(agentPEM); err == nil {
			issuedSerials[cert.SerialNumber.String()] = hostname
		}
		ln, err := proto.Listen("127.0.0.1:0", agentID, pool)
		if err != nil {
			t.Fatal(err)
		}
		a := agent.New(agent.Options{
			Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		})
		cluster.wg.Add(1)
		go func() {
			defer cluster.wg.Done()
			_ = a.Serve(ctx, ln)
		}()
		cluster.Targets = append(cluster.Targets, runner.Target{
			Hostname:   hostname,
			Addr:       ln.Addr().String(),
			ServerName: "localhost",
		})
	}
	t.Cleanup(func() {
		cancel()
		cluster.wg.Wait()
	})
	return cluster
}

// fileOp builds a simple file op writing content to path.
func fileOp(path, content string) proto.Op {
	return proto.Op{
		OpType: proto.OpTypeFile,
		File:   &proto.FileOp{Path: path, Content: content, Mode: "0644"},
	}
}

func TestRunAcrossHosts(t *testing.T) {
	cluster := startCluster(t, 2)
	dir := t.TempDir()

	specs := make([]runner.HostSpec, 0, len(cluster.Targets))
	for _, target := range cluster.Targets {
		path := filepath.Join(dir, target.Hostname+".txt")
		specs = append(specs, runner.HostSpec{
			Target: target,
			Ops:    []proto.Op{fileOp(path, "hello from "+target.Hostname)},
		})
	}

	report, err := runner.Run(context.Background(), runner.Request{
		Hosts:      specs,
		Identity:   cluster.Identity,
		ServerPool: cluster.ServerPool,
	}, runner.Options{MaxFailures: -1})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !report.Succeeded() {
		t.Fatalf("run not succeeded: %+v", report)
	}
	if report.Changed != 2 || report.OK != 2 {
		t.Errorf("totals = ok %d changed %d, want 2/2", report.OK, report.Changed)
	}
	for _, target := range cluster.Targets {
		data, err := os.ReadFile(filepath.Join(dir, target.Hostname+".txt"))
		if err != nil {
			t.Errorf("%s: file not written: %v", target.Hostname, err)
			continue
		}
		if want := "hello from " + target.Hostname; string(data) != want {
			t.Errorf("%s content = %q, want %q", target.Hostname, data, want)
		}
	}
}

func TestRunIdempotentSecondPass(t *testing.T) {
	cluster := startCluster(t, 1)
	dir := t.TempDir()
	path := filepath.Join(dir, "conf.txt")
	specs := []runner.HostSpec{{
		Target: cluster.Targets[0],
		Ops:    []proto.Op{fileOp(path, "stable")},
	}}
	req := runner.Request{Hosts: specs, Identity: cluster.Identity, ServerPool: cluster.ServerPool}
	opts := runner.Options{MaxFailures: -1}

	first, err := runner.Run(context.Background(), req, opts)
	if err != nil {
		t.Fatal(err)
	}
	if first.Changed != 1 {
		t.Fatalf("first run changed = %d, want 1", first.Changed)
	}
	second, err := runner.Run(context.Background(), req, opts)
	if err != nil {
		t.Fatal(err)
	}
	if second.Changed != 0 {
		t.Errorf("second run changed = %d, want 0 (idempotence)", second.Changed)
	}
	if second.OK != 1 {
		t.Errorf("second run ok = %d, want 1", second.OK)
	}
}

func TestRunCheckModeMutatesNothing(t *testing.T) {
	cluster := startCluster(t, 1)
	dir := t.TempDir()
	path := filepath.Join(dir, "check.txt")

	report, err := runner.Run(context.Background(), runner.Request{
		Hosts: []runner.HostSpec{{
			Target: cluster.Targets[0],
			Ops:    []proto.Op{fileOp(path, "x")},
		}},
		Identity:   cluster.Identity,
		ServerPool: cluster.ServerPool,
	}, runner.Options{Check: true, MaxFailures: -1})
	if err != nil {
		t.Fatal(err)
	}
	if report.Changed != 1 {
		t.Errorf("check mode changed = %d, want 1 (would-change)", report.Changed)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("check mode created %s", path)
	}
}

func TestRunUnreachableHostFails(t *testing.T) {
	cluster := startCluster(t, 1)
	// A target pointing at a closed port: dial must fail cleanly.
	closed := cluster.Targets[0]
	closed.Addr = "127.0.0.1:1"
	specs := []runner.HostSpec{{
		Target: closed,
		Ops:    []proto.Op{fileOp(filepath.Join(t.TempDir(), "never.txt"), "x")},
	}}

	report, err := runner.Run(context.Background(), runner.Request{
		Hosts:      specs,
		Identity:   cluster.Identity,
		ServerPool: cluster.ServerPool,
	}, runner.Options{MaxFailures: -1})
	if err != nil {
		t.Fatalf("Run returned request error: %v", err)
	}
	if report.Succeeded() {
		t.Fatal("run succeeded despite an unreachable host")
	}
	if report.FailedHosts != 1 {
		t.Errorf("failed hosts = %d, want 1", report.FailedHosts)
	}
	if report.Results[0].Err == nil {
		t.Error("host result has no error")
	}
	if report.Err() == nil {
		t.Error("report.Err() = nil after host failure")
	}
}

func TestRunFailFastSkipsRemaining(t *testing.T) {
	cluster := startCluster(t, 3)
	// Host 0 is unreachable (counts as first failure); with MaxFailures=0
	// the rest must be skipped.
	specs := []runner.HostSpec{
		{
			Target: runner.Target{Hostname: cluster.Targets[0].Hostname, Addr: "127.0.0.1:1", ServerName: "localhost"},
			Ops:    []proto.Op{fileOp(filepath.Join(t.TempDir(), "a.txt"), "x")},
		},
		{
			Target: cluster.Targets[1],
			Ops:    []proto.Op{fileOp(filepath.Join(t.TempDir(), "b.txt"), "x")},
		},
		{
			Target: cluster.Targets[2],
			Ops:    []proto.Op{fileOp(filepath.Join(t.TempDir(), "c.txt"), "x")},
		},
	}

	report, err := runner.Run(context.Background(), runner.Request{
		Hosts:      specs,
		Identity:   cluster.Identity,
		ServerPool: cluster.ServerPool,
	}, runner.Options{MaxFailures: 0, Parallelism: 1})
	if err != nil {
		t.Fatal(err)
	}
	if report.FailedHosts != 1 {
		t.Errorf("failed hosts = %d, want 1", report.FailedHosts)
	}
	if report.Skipped == 0 {
		t.Errorf("skipped = %d, want > 0 after fail-fast", report.Skipped)
	}
	if report.Succeeded() {
		t.Error("report.Succeeded() after fail-fast")
	}
}

func TestRunValidation(t *testing.T) {
	if _, err := runner.Run(context.Background(), runner.Request{}, runner.Options{}); err == nil {
		t.Error("Run accepted an empty request")
	}
	cluster := startCluster(t, 1)
	specs := []runner.HostSpec{{Target: cluster.Targets[0]}}
	if _, err := runner.Run(context.Background(), runner.Request{
		Hosts:      specs,
		Identity:   cluster.Identity,
		ServerPool: nil,
	}, runner.Options{}); err == nil {
		t.Error("Run accepted a nil server pool")
	}
	if _, err := runner.Run(context.Background(), runner.Request{
		Hosts:      specs,
		Identity:   proto.Identity{},
		ServerPool: cluster.ServerPool,
	}, runner.Options{}); err == nil {
		t.Error("Run accepted an empty identity")
	}
}

func TestRunParallelAcrossHosts(t *testing.T) {
	cluster := startCluster(t, 4)
	dir := t.TempDir()
	specs := make([]runner.HostSpec, 0, 4)
	for _, target := range cluster.Targets {
		specs = append(specs, runner.HostSpec{
			Target: target,
			Ops:    []proto.Op{fileOp(filepath.Join(dir, target.Hostname), "x")},
		})
	}

	start := time.Now()
	report, err := runner.Run(context.Background(), runner.Request{
		Hosts:      specs,
		Identity:   cluster.Identity,
		ServerPool: cluster.ServerPool,
	}, runner.Options{MaxFailures: -1, Parallelism: 4})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Succeeded() || report.Changed != 4 {
		t.Fatalf("run = %+v", report)
	}
	// 4 hosts, 4 workers: nothing to assert about wall time strictly, but
	// keep it bounded so a serial regression would still pass tests fast.
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Errorf("parallel run took %v", elapsed)
	}
}

// TestRunRefusesRevokedAgent: a host whose certificate serial the
// IsRevoked hook reports as revoked fails before any ops flow.
func TestRunRefusesRevokedAgent(t *testing.T) {
	cluster := startCluster(t, 2)
	revoked := map[string]bool{cluster.Targets[0].Hostname: true}
	// The hook stands in for the inventory: keyed by hostname here, but
	// production wires inv.IsRevoked (keyed by cert serial).
	hook := func(serial string) (bool, error) {
		return revoked[serialToHost(serial, cluster)], nil
	}
	dir := t.TempDir()
	specs := []runner.HostSpec{
		{Target: cluster.Targets[0], Ops: []proto.Op{fileOp(filepath.Join(dir, "a.txt"), "x")}},
		{Target: cluster.Targets[1], Ops: []proto.Op{fileOp(filepath.Join(dir, "b.txt"), "x")}},
	}
	report, err := runner.Run(context.Background(), runner.Request{
		Hosts:      specs,
		Identity:   cluster.Identity,
		ServerPool: cluster.ServerPool,
		IsRevoked:  hook,
	}, runner.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Results[0].HasFailure() || report.Results[0].Err == nil {
		t.Errorf("revoked host err = %v, want failure", report.Results[0].Err)
	} else if !strings.Contains(report.Results[0].Err.Error(), "REVOKED") {
		t.Errorf("err = %v, want a REVOKED error", report.Results[0].Err)
	}
	if report.Results[1].HasFailure() {
		t.Errorf("unrevoked host failed: %v", report.Results[1].Err)
	}
}

// serialToHost maps an agent serial to its hostname via the issued
// certs recorded by startCluster (test-only helper: production keys by
// serial directly via inv.IsRevoked).
func serialToHost(serial string, cluster *testCluster) string {
	if h, ok := issuedSerials[serial]; ok {
		return h
	}
	return serial // unknown serial: not revoked
}

// TestRunFailsClosedOnRevocationCheckError: a hook error must fail the
// host, never apply anyway.
func TestRunFailsClosedOnRevocationCheckError(t *testing.T) {
	cluster := startCluster(t, 1)
	hook := func(serial string) (bool, error) {
		return false, errors.New("inventory unavailable")
	}
	report, err := runner.Run(context.Background(), runner.Request{
		Hosts: []runner.HostSpec{
			{Target: cluster.Targets[0], Ops: []proto.Op{fileOp(filepath.Join(t.TempDir(), "a.txt"), "x")}},
		},
		Identity:   cluster.Identity,
		ServerPool: cluster.ServerPool,
		IsRevoked:  hook,
	}, runner.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Results[0].HasFailure() || !strings.Contains(report.Results[0].Err.Error(), "failing closed") {
		t.Errorf("err = %v, want fail-closed error", report.Results[0].Err)
	}
}
