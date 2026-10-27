package proto

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/claymod/claymod/internal/ca"
)

func marshalResult(v any) (json.RawMessage, error) { return json.Marshal(v) }

func mustMarshal(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func unmarshalParams(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		return errors.New("empty params")
	}
	return json.Unmarshal(raw, v)
}

// makeTestCA creates a throwaway CA and issues a server identity
// (CN=claymod-server, SAN=claymod.test) and a client identity (CN=web01).
func makeTestCA(t *testing.T) (authority *ca.CA, serverID, clientID Identity, pool *x509.CertPool) {
	t.Helper()
	authority, err := ca.New("proto-test-ca")
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
		CommonName: "web01",
		Usage:      ca.UsageClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	serverID, err = LoadIdentity(serverPEM, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	clientID, err = LoadIdentity(clientPEM, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	pool = authority.Pool()
	return authority, serverID, clientID, pool
}

// dialTestTLS opens a raw TLS client connection (completing the TLS
// handshake only) to addr.
func dialTestTLS(t *testing.T, addr string, clientID Identity, pool *x509.CertPool) (*tls.Conn, error) {
	t.Helper()
	cfg := &tls.Config{
		Certificates: []tls.Certificate{clientID.Certificate},
		RootCAs:      pool,
		ServerName:   "claymod.test",
		MinVersion:   tls.VersionTLS13,
	}
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	tconn := tls.Client(raw, cfg)
	if err := tconn.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	return tconn, nil
}

// testPair spins up an in-memory mutual-TLS connection pair using certs
// from a throwaway CA, and completes the handshake on both sides.
func testPair(t *testing.T) (client, server *Conn) {
	t.Helper()
	_, serverID, clientID, pool := makeTestCA(t)

	ln, err := Listen("127.0.0.1:0", serverID, pool)
	if err != nil {
		t.Fatalf("Listen returned error: %v", err)
	}
	defer ln.Close()

	var wg sync.WaitGroup
	var srvConn *Conn
	var srvErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		raw, err := ln.Accept()
		if err != nil {
			srvErr = err
			return
		}
		srvConn, srvErr = Server(raw, DefaultFrameTimeout)
	}()

	cliConn, err := Dial(ln.Addr().String(), "claymod.test", clientID, pool)
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	wg.Wait()
	if srvErr != nil {
		t.Fatalf("server handshake returned error: %v", srvErr)
	}
	t.Cleanup(func() {
		cliConn.Close()
		srvConn.Close()
	})
	return cliConn, srvConn
}

func TestHandshakeVersionsMatch(t *testing.T) {
	client, server := testPair(t)
	if client.Peer().Role != RoleAgent {
		t.Errorf("client sees peer role %q, want %q", client.Peer().Role, RoleAgent)
	}
	if server.Peer().Role != RoleServer {
		t.Errorf("server sees peer role %q, want %q", server.Peer().Role, RoleServer)
	}
	if client.Peer().Version != Version || server.Peer().Version != Version {
		t.Errorf("handshake version mismatch: client=%d server=%d",
			client.Peer().Version, server.Peer().Version)
	}
}

func TestVersionMismatchRejected(t *testing.T) {
	// Hand-rolled: a peer that sends a different version must be refused.
	authority, err := ca.New("proto-test-ca")
	if err != nil {
		t.Fatal(err)
	}
	serverPEM, serverKey, err := authority.IssueCert(ca.IssueOptions{
		CommonName: "claymod-server", Usage: ca.UsageServer, DNSNames: []string{"claymod.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	clientPEM, clientKey, err := authority.IssueCert(ca.IssueOptions{
		CommonName: "web01", Usage: ca.UsageClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	serverID, err := LoadIdentity(serverPEM, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	clientID, err := LoadIdentity(clientPEM, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := authority.Pool()

	ln, err := Listen("127.0.0.1:0", serverID, pool)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		conn, err := Server(raw, time.Second)
		if conn != nil {
			conn.Close()
		}
		errCh <- err
	}()

	// Dumb raw TLS client speaking the wrong version.
	cfg := &tls.Config{
		Certificates: []tls.Certificate{clientID.Certificate},
		RootCAs:      pool,
		ServerName:   "claymod.test",
		MinVersion:   tls.VersionTLS13,
	}
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	tconn := tls.Client(raw, cfg)
	if err := tconn.Handshake(); err != nil {
		t.Fatalf("tls handshake: %v", err)
	}
	// Send a bogus handshake frame: {version:99, role:"server"}.
	bogus := Handshake{Version: 99, Role: RoleServer}
	c := &Conn{tls: tconn, timeout: time.Second}
	if err := c.Send(bogus); err != nil {
		t.Fatalf("send bogus handshake: %v", err)
	}

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("Server accepted a peer with version 99")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not respond to bogus handshake")
	}
}

func TestRequestResponseRoundTrip(t *testing.T) {
	client, server := testPair(t)

	// Server (agent) side: answer a Ping.
	go func() {
		var req Request
		if err := server.Recv(&req); err != nil {
			t.Error("server recv:", err)
			return
		}
		result, _ := marshalResult(PingResult{Version: Version, Agent: "test-agent"})
		if err := server.Send(Response{ID: req.ID, Result: result}); err != nil {
			t.Error("server send:", err)
		}
	}()

	var ping PingResult
	rpcErr, err := client.Call(Request{ID: "req-1", Method: MethodPing}, &ping)
	if err != nil {
		t.Fatalf("Call returned error: %v", err)
	}
	if rpcErr != nil {
		t.Fatalf("Call returned rpc error: %v", rpcErr)
	}
	if ping.Version != Version || ping.Agent != "test-agent" {
		t.Errorf("ping result = %+v", ping)
	}
}

func TestCallErrorPropagates(t *testing.T) {
	client, server := testPair(t)

	go func() {
		var req Request
		if err := server.Recv(&req); err != nil {
			t.Error("server recv:", err)
			return
		}
		if err := server.Send(Response{
			ID:    req.ID,
			Error: &Error{Code: CodeUnsupported, Message: "no such method"},
		}); err != nil {
			t.Error("server send:", err)
		}
	}()

	rpcErr, err := client.Call(Request{ID: "req-2", Method: "Nope"}, nil)
	if err != nil {
		t.Fatalf("Call returned transport error: %v", err)
	}
	if rpcErr == nil || rpcErr.Code != CodeUnsupported {
		t.Fatalf("rpcErr = %v, want code %q", rpcErr, CodeUnsupported)
	}
}

func TestMismatchedResponseIDRejected(t *testing.T) {
	client, server := testPair(t)

	go func() {
		var req Request
		if err := server.Recv(&req); err != nil {
			return
		}
		server.Send(Response{ID: "wrong-id", Result: nil})
	}()

	_, err := client.Call(Request{ID: "req-3", Method: MethodPing}, nil)
	if err == nil {
		t.Fatal("Call accepted a response with the wrong id")
	}
}

func TestRawTransportWithoutTLSRejected(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	_, err := Server(c2, time.Second)
	if err == nil {
		t.Fatal("Server accepted a non-TLS connection")
	}
}

func TestRecvEOFOnPeerClose(t *testing.T) {
	client, server := testPair(t)
	server.Close()
	var req Request
	err := client.Recv(&req)
	if err == nil {
		t.Fatal("Recv succeeded after peer closed")
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		// TLS close may surface as a connection error; any non-nil error
		// is acceptable, but assert it's not a panic/hang.
		t.Logf("recv after close returned: %v", err)
	}
}

func TestApplyStreams(t *testing.T) {
	client, server := testPair(t)

	ops := []Op{
		{OpType: OpTypeFile, File: &FileOp{Path: "/tmp/a", Content: "x"}},
		{OpType: OpTypeCommand, Command: &CommandOp{Shell: "true"}},
	}

	go func() {
		var req Request
		if err := server.Recv(&req); err != nil {
			t.Error("server recv:", err)
			return
		}
		var params ApplyParams
		if err := unmarshalParams(req.Params, &params); err != nil {
			t.Error("unmarshal params:", err)
			return
		}
		for k := range params.Ops {
			res := ApplyResult{Index: k, OpType: params.Ops[k].OpType, Changed: k == 0}
			if err := server.Send(Response{ID: req.ID, Result: mustMarshal(res)}); err != nil {
				t.Error("server send:", err)
				return
			}
		}
		summary := ApplyResult{Summary: true, OK: 2, Changes: 1}
		server.Send(Response{ID: req.ID, Result: mustMarshal(summary)})
	}()

	req := Request{ID: "run-1", Method: MethodApply, Params: mustMarshal(ApplyParams{Ops: ops, Check: true})}
	if err := client.Send(req); err != nil {
		t.Fatal(err)
	}
	var got []ApplyResult
	for {
		var resp Response
		if err := client.Recv(&resp); err != nil {
			t.Fatalf("recv: %v", err)
		}
		if resp.ID != req.ID {
			t.Fatalf("response id %q != request id", resp.ID)
		}
		var r ApplyResult
		if err := unmarshalParams(resp.Result, &r); err != nil {
			t.Fatal(err)
		}
		got = append(got, r)
		if r.Summary {
			break
		}
	}
	if len(got) != 3 {
		t.Fatalf("got %d results, want 3 (2 ops + summary)", len(got))
	}
	if !got[2].Summary || got[2].Changes != 1 {
		t.Errorf("summary = %+v", got[2])
	}
}
