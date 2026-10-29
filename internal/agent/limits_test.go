package agent

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/claymod/claymod/internal/ca"
	"github.com/claymod/claymod/internal/proto"
)

// blockingService blocks State until released: it holds a session open
// so the cap test can observe backpressure.
type blockingService struct {
	fakeService
	release chan struct{}
}

func (b *blockingService) State(_ context.Context, _ string) (string, error) {
	<-b.release
	return "active", nil
}

// panickingService panics in State: a hostile/buggy module must kill the
// session, not the daemon.
type panickingService struct {
	fakeService
}

func (p *panickingService) State(_ context.Context, _ string) (string, error) {
	panic("boom: hostile module")
}

func serviceOp() proto.Op {
	// Enabled omitted: the State path only (a nil-map Enable in the
	// embedded fake would panic and defeat the test's purpose).
	return proto.Op{
		OpType:  proto.OpTypeService,
		Service: &proto.ServiceOp{Unit: "nginx", State: proto.StateStarted},
	}
}

// callApplyStreamError drives one Apply run and returns the first
// error (transport or op) without failing the test.
func callApplyStreamError(conn *proto.Conn, op proto.Op) error {
	req := proto.Request{ID: "apply-x", Method: proto.MethodApply}
	raw, err := json.Marshal(proto.ApplyParams{Ops: []proto.Op{op}})
	if err != nil {
		return err
	}
	req.Params = raw
	if err := conn.Send(req); err != nil {
		return err
	}
	for {
		var resp proto.Response
		if err := conn.Recv(&resp); err != nil {
			return err
		}
		if resp.Error != nil {
			return errors.New(resp.Error.Message)
		}
		var r proto.ApplyResult
		if err := json.Unmarshal(resp.Result, &r); err != nil {
			return err
		}
		if r.Summary {
			return nil
		}
	}
}

// startAgentHold is startAgent with the raw dial coordinates returned
// so tests can open further connections themselves.
func startAgentHold(t *testing.T, opts Options) (conn *proto.Conn, addr string, clientID proto.Identity, pool *x509.CertPool) {
	t.Helper()
	authority, err := ca.New("agent-limit-ca")
	if err != nil {
		t.Fatal(err)
	}
	serverPEM, serverKey, err := authority.IssueCert(ca.IssueOptions{
		CommonName: "claymod-server",
		Usage:      ca.UsageServer,
		DNSNames:   []string{"claymod.test"},
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
	clientID, err = proto.LoadIdentity(clientPEM, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	pool = authority.Pool()
	ln, err := proto.Listen("127.0.0.1:0", serverID, pool)
	if err != nil {
		t.Fatal(err)
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	a := New(opts)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = a.Serve(ctx, ln)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	conn, err = proto.Dial(ln.Addr().String(), "claymod.test", clientID, pool)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn, ln.Addr().String(), clientID, pool
}

// dialAgent opens one more control connection to a started agent.
func dialAgent(t *testing.T, addr string, clientID proto.Identity, pool *x509.CertPool) (*proto.Conn, error) {
	return proto.Dial(addr, "claymod.test", clientID, pool)
}

// TestAgentSurvivesPanickingSession: an op that panics kills the
// session, not the daemon — the next connection still serves.
func TestAgentSurvivesPanickingSession(t *testing.T) {
	conn := startAgent(t, Options{Services: &panickingService{}})

	errCh := make(chan error, 1)
	go func() {
		errCh <- callApplyStreamError(conn, serviceOp())
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("panicking session produced no error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("panicking session hung the agent")
	}

	// The agent must still be alive and serving new sessions: a fresh
	// Ping on a NEW connection succeeds.
	conn2 := startAgent(t, Options{})
	var ping proto.PingResult
	if _, err := conn2.Call(proto.Request{ID: "p2", Method: proto.MethodPing}, &ping); err != nil {
		t.Fatalf("agent did not serve after a panicking session: %v", err)
	}
}

// TestAgentCapsConcurrentSessions: with MaxConns=1, a second connection
// cannot complete its handshake while the first session holds the only
// slot; it proceeds once that session ends (backpressure, not
// unbounded growth).
func TestAgentCapsConcurrentSessions(t *testing.T) {
	release := make(chan struct{})

	// MaxConns=1 agent; first connection holds the slot.
	opts := Options{MaxConns: 1, Services: &blockingService{release: release}}
	conn1, addr, clientID, pool := startAgentHold(t, opts)

	done1 := make(chan error, 1)
	go func() {
		done1 <- callApplyStreamError(conn1, serviceOp())
	}()
	time.Sleep(200 * time.Millisecond) // let session 1 acquire the slot

	type dialResult struct {
		conn *proto.Conn
		err  error
	}
	dialCh := make(chan dialResult, 1)
	go func() {
		conn, err := dialAgent(t, addr, clientID, pool)
		dialCh <- dialResult{conn, err}
	}()

	select {
	case r := <-dialCh:
		t.Fatalf("second connection completed despite the cap (err=%v)", r.err)
	case <-time.After(500 * time.Millisecond):
		// Expected: the handshake is parked waiting for a slot.
	}

	close(release) // end session 1's in-flight op
	if err := <-done1; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("first session errored: %v", err)
	}
	// The cap is per-SESSION: free the slot by closing conn1 itself.
	conn1.Close()
	select {
	case r := <-dialCh:
		if r.err != nil {
			t.Fatalf("second connection failed after release: %v", r.err)
		}
		r.conn.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("second connection never completed after release")
	}
}
