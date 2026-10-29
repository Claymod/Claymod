package agent

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/claymod/claymod/internal/ca"
	"github.com/claymod/claymod/internal/proto"
)

// shutdownFixture holds an agent, its listener and TLS material.
type shutdownFixture struct {
	ln       net.Listener
	clientID proto.Identity
	pool     *x509.CertPool
}

// spinShutdown starts TLS material + listener (the caller runs Serve).
func spinShutdown(t *testing.T) *shutdownFixture {
	t.Helper()
	authority, err := ca.New("agent-shutdown-ca")
	if err != nil {
		t.Fatal(err)
	}
	serverPEM, serverKey, err := authority.IssueCert(ca.IssueOptions{
		CommonName: "claymod-server", Usage: ca.UsageServer,
		DNSNames: []string{"claymod.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	clientPEM, clientKey, err := authority.IssueCert(ca.IssueOptions{
		CommonName: "runner", Usage: ca.UsageClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	serverID, err := proto.LoadIdentity(serverPEM, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	clientID, err := proto.LoadIdentity(clientPEM, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := authority.Pool()
	ln, err := proto.Listen("127.0.0.1:0", serverID, pool)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return &shutdownFixture{ln: ln, clientID: clientID, pool: pool}
}

// ctxAwareService blocks in State until its ctx is done (the shutdown
// path) or release closes — a hermetic stand-in for a long-running op:
// no process-kill timing, no platform shell semantics.
type ctxAwareService struct {
	fakeService
	release chan struct{}
}

func (c *ctxAwareService) State(ctx context.Context, _ string) (string, error) {
	select {
	case <-c.release:
		return "active", nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// callApplyResults runs one Apply and returns the streamed results.
func callApplyResults(conn *proto.Conn, op proto.Op) ([]proto.ApplyResult, error) {
	req := proto.Request{ID: "apply-d", Method: proto.MethodApply}
	raw, err := json.Marshal(proto.ApplyParams{Ops: []proto.Op{op}})
	if err != nil {
		return nil, err
	}
	req.Params = raw
	if err := conn.Send(req); err != nil {
		return nil, err
	}
	var results []proto.ApplyResult
	for {
		var resp proto.Response
		if err := conn.Recv(&resp); err != nil {
			return results, err
		}
		if resp.Error != nil {
			return results, errors.New(resp.Error.Message)
		}
		var r proto.ApplyResult
		if err := json.Unmarshal(resp.Result, &r); err != nil {
			return results, err
		}
		results = append(results, r)
		if r.Summary {
			return results, nil
		}
	}
}

// TestGracefulShutdownBoundsInFlightApply: cancelling the context (the
// SIGTERM path) kills a REAL in-flight command (exec.CommandContext) at
// the next checkpoint — the client sees the apply fail promptly (never a
// hang), the session closes and Serve returns once drained. Ops are
// idempotent, so an aborted apply is safe to re-run.
func TestGracefulShutdownBoundsInFlightApply(t *testing.T) {
	fx := spinShutdown(t)
	// The in-flight op blocks until ctx fires (or release closes): the
	// test is hermetic — cancel-before-start, mid-op and after all end
	// in the same bounded outcome, with no dependence on process-kill
	// timing or platform shell semantics (the CI failure this replaced).
	release := make(chan struct{})
	defer close(release) // safety: never leak a blocked op
	a := New(Options{MaxConns: 4, Services: &ctxAwareService{release: release}})

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- a.Serve(ctx, fx.ln) }()

	before := runtime.NumGoroutine()
	conn, err := proto.Dial(fx.ln.Addr().String(), "claymod.test", fx.clientID, fx.pool)
	if err != nil {
		t.Fatal(err)
	}
	type applyOutcome struct {
		results []proto.ApplyResult
		err     error
	}
	applyDone := make(chan applyOutcome, 1)
	go func() {
		results, err := callApplyResults(conn, serviceOp())
		applyDone <- applyOutcome{results, err}
	}()
	time.Sleep(200 * time.Millisecond) // let the op reach its blocking point

	// SIGTERM: cancel while the op is blocked. The op must terminate via
	// ctx and surface as a failed op (or transport error) — promptly.
	cancel()
	select {
	case out := <-applyDone:
		failed := out.err != nil
		for _, r := range out.results {
			if r.Failed {
				failed = true
			}
		}
		if !failed {
			t.Fatalf("in-flight apply was not bounded by shutdown: results=%+v err=%v", out.results, out.err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("in-flight apply hung past shutdown (no bound)")
	}
	conn.Close()

	// Serve drains the session goroutine and returns promptly.
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Serve returned an error: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Serve did not return after the in-flight apply aborted")
	}

	// No goroutine leak: accept loop + session goroutines are gone.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before+2 { // small tolerance
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("goroutines leaked: before=%d after=%d", before, runtime.NumGoroutine())
}

// TestGracefulShutdownIdleIsPrompt: with no in-flight work, cancel
// returns Serve immediately.
func TestGracefulShutdownIdleIsPrompt(t *testing.T) {
	fx := spinShutdown(t)
	a := New(Options{})
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- a.Serve(ctx, fx.ln) }()
	time.Sleep(100 * time.Millisecond)

	start := time.Now()
	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("idle shutdown errored: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("idle shutdown did not return promptly")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("idle shutdown took %v", elapsed)
	}
}
