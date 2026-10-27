package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/claymod/claymod/internal/ca"
	"github.com/claymod/claymod/internal/proto"
)

// startAgent spins up an agent on a loopback port with throwaway certs and
// returns a client-side connection to it.
func startAgent(t *testing.T, opts Options) *proto.Conn {
	t.Helper()
	authority, err := ca.New("agent-test-ca")
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
		CommonName: "runner",
		Usage:      ca.UsageClient,
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
		t.Fatalf("Listen returned error: %v", err)
	}

	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	}
	a := New(opts)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = a.Serve(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})

	conn, err := proto.Dial(ln.Addr().String(), "claymod.test", clientID, pool)
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// callApply drives one Apply run and collects the streamed results.
func callApply(t *testing.T, conn *proto.Conn, params proto.ApplyParams) []proto.ApplyResult {
	t.Helper()
	req := proto.Request{ID: "apply-1", Method: proto.MethodApply}
	raw, err := marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	req.Params = raw
	if err := conn.Send(req); err != nil {
		t.Fatal(err)
	}
	var got []proto.ApplyResult
	for {
		var resp proto.Response
		if err := conn.Recv(&resp); err != nil {
			t.Fatalf("recv: %v", err)
		}
		if resp.Error != nil {
			t.Fatalf("apply error: %v", resp.Error)
		}
		var r proto.ApplyResult
		if err := unmarshal(resp.Result, &r); err != nil {
			t.Fatal(err)
		}
		got = append(got, r)
		if r.Summary {
			return got
		}
	}
}

func TestPingFacts(t *testing.T) {
	conn := startAgent(t, Options{})

	var ping proto.PingResult
	rpcErr, err := conn.Call(proto.Request{ID: "p1", Method: proto.MethodPing}, &ping)
	if err != nil || rpcErr != nil {
		t.Fatalf("Ping: err=%v rpcErr=%v", err, rpcErr)
	}
	if ping.Version != proto.Version {
		t.Errorf("Ping version = %d, want %d", ping.Version, proto.Version)
	}

	var facts proto.FactsResult
	rpcErr, err = conn.Call(proto.Request{ID: "p2", Method: proto.MethodFacts}, &facts)
	if err != nil || rpcErr != nil {
		t.Fatalf("Facts: err=%v rpcErr=%v", err, rpcErr)
	}
	if facts.Hostname == "" || facts.OS == "" {
		t.Errorf("Facts incomplete: %+v", facts)
	}
}

func TestApplyFileCreateAndIdempotence(t *testing.T) {
	conn := startAgent(t, Options{})
	path := filepath.Join(t.TempDir(), "hello.txt")

	// First apply: creates the file (changed=true).
	results := callApply(t, conn, proto.ApplyParams{
		Ops: []proto.Op{{
			OpType: proto.OpTypeFile,
			File:   &proto.FileOp{Path: path, Content: "hello", Mode: "0644"},
		}},
	})
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2 (op + summary)", len(results))
	}
	if !results[0].Changed || results[0].Failed {
		t.Errorf("first apply result = %+v, want changed", results[0])
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Errorf("file content = %q, want hello", data)
	}

	// Second apply: unchanged (idempotence).
	results = callApply(t, conn, proto.ApplyParams{
		Ops: []proto.Op{{
			OpType: proto.OpTypeFile,
			File:   &proto.FileOp{Path: path, Content: "hello", Mode: "0644"},
		}},
	})
	if results[0].Changed {
		t.Errorf("second apply reported changed: %+v", results[0])
	}
	if results[0].Failed {
		t.Errorf("second apply failed: %+v", results[0])
	}
	if results[1].Summary && results[1].Changes != 0 {
		t.Errorf("summary changes = %d, want 0", results[1].Changes)
	}
}

func TestApplyFileUpdateOnChange(t *testing.T) {
	conn := startAgent(t, Options{})
	path := filepath.Join(t.TempDir(), "conf.txt")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	results := callApply(t, conn, proto.ApplyParams{
		Ops: []proto.Op{{
			OpType: proto.OpTypeFile,
			File:   &proto.FileOp{Path: path, Content: "new", Mode: "0644"},
		}},
	})
	if !results[0].Changed {
		t.Errorf("update not detected: %+v", results[0])
	}
	data, _ := os.ReadFile(path)
	if string(data) != "new" {
		t.Errorf("content = %q, want new", data)
	}
}

func TestApplyCheckModeMutatesNothing(t *testing.T) {
	conn := startAgent(t, Options{})
	path := filepath.Join(t.TempDir(), "check.txt")

	results := callApply(t, conn, proto.ApplyParams{
		Check: true,
		Ops: []proto.Op{{
			OpType: proto.OpTypeFile,
			File:   &proto.FileOp{Path: path, Content: "x", Mode: "0644"},
		}},
	})
	if !results[0].Changed {
		t.Errorf("check mode did not report would-change: %+v", results[0])
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("check mode created %s (stat err = %v)", path, err)
	}
}

func TestApplyFileAbsent(t *testing.T) {
	conn := startAgent(t, Options{})
	path := filepath.Join(t.TempDir(), "gone.txt")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	results := callApply(t, conn, proto.ApplyParams{
		Ops: []proto.Op{{
			OpType: proto.OpTypeFile,
			File:   &proto.FileOp{Path: path, Ensure: proto.EnsureAbsent},
		}},
	})
	if !results[0].Changed {
		t.Errorf("absent not applied: %+v", results[0])
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("file still exists after absent")
	}
}

func TestApplyFileRejectsRelativePath(t *testing.T) {
	conn := startAgent(t, Options{})
	results := callApply(t, conn, proto.ApplyParams{
		Ops: []proto.Op{{
			OpType: proto.OpTypeFile,
			File:   &proto.FileOp{Path: "relative/path.txt", Content: "x"},
		}},
	})
	if !results[0].Failed {
		t.Errorf("relative path accepted: %+v", results[0])
	}
}

func TestApplyFileBackup(t *testing.T) {
	conn := startAgent(t, Options{})
	dir := t.TempDir()
	path := filepath.Join(dir, "conf.txt")
	if err := os.WriteFile(path, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	results := callApply(t, conn, proto.ApplyParams{
		Ops: []proto.Op{{
			OpType: proto.OpTypeFile,
			File:   &proto.FileOp{Path: path, Content: "updated", Mode: "0644", Backup: true},
		}},
	})
	if results[0].Failed {
		t.Fatalf("backup apply failed: %+v", results[0])
	}
	backup, err := os.ReadFile(path + ".bak")
	if err != nil {
		t.Fatalf("backup not written: %v", err)
	}
	if string(backup) != "original" {
		t.Errorf("backup content = %q, want original", backup)
	}
}

func TestApplyCommandRuns(t *testing.T) {
	conn := startAgent(t, Options{})
	marker := filepath.Join(t.TempDir(), "ran.txt")

	results := callApply(t, conn, proto.ApplyParams{
		Ops: []proto.Op{{
			OpType:  proto.OpTypeCommand,
			Command: &proto.CommandOp{Shell: "echo hi > " + marker},
		}},
	})
	if results[0].Failed {
		t.Fatalf("command failed: %+v", results[0])
	}
	if !results[0].Changed {
		t.Errorf("command not reported as changed: %+v", results[0])
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("command had no effect: %v", err)
	}
}

func TestApplyCommandGuards(t *testing.T) {
	conn := startAgent(t, Options{})

	// only_if false → skipped.
	results := callApply(t, conn, proto.ApplyParams{
		Ops: []proto.Op{{
			OpType:  proto.OpTypeCommand,
			Command: &proto.CommandOp{Shell: "false", OnlyIf: "false"},
		}},
	})
	if results[0].Failed || results[0].Changed {
		t.Errorf("only_if false should skip: %+v", results[0])
	}

	// unless_if true → skipped.
	results = callApply(t, conn, proto.ApplyParams{
		Ops: []proto.Op{{
			OpType:  proto.OpTypeCommand,
			Command: &proto.CommandOp{Shell: "false", UnlessIf: "true"},
		}},
	})
	if results[0].Failed || results[0].Changed {
		t.Errorf("unless_if true should skip: %+v", results[0])
	}

	// creates existing → skipped.
	existing := filepath.Join(t.TempDir(), "exists.txt")
	if err := os.WriteFile(existing, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	results = callApply(t, conn, proto.ApplyParams{
		Ops: []proto.Op{{
			OpType:  proto.OpTypeCommand,
			Command: &proto.CommandOp{Shell: "false", Creates: existing},
		}},
	})
	if results[0].Failed || results[0].Changed {
		t.Errorf("creates existing should skip: %+v", results[0])
	}

	// removes absent → skipped.
	results = callApply(t, conn, proto.ApplyParams{
		Ops: []proto.Op{{
			OpType:  proto.OpTypeCommand,
			Command: &proto.CommandOp{Shell: "false", Removes: "/nonexistent-claymod-test"},
		}},
	})
	if results[0].Failed || results[0].Changed {
		t.Errorf("removes absent should skip: %+v", results[0])
	}
}

func TestApplyCommandFailure(t *testing.T) {
	conn := startAgent(t, Options{})
	results := callApply(t, conn, proto.ApplyParams{
		Ops: []proto.Op{{
			OpType:  proto.OpTypeCommand,
			Command: &proto.CommandOp{Shell: "echo oops >&2; exit 3"},
		}},
	})
	if !results[0].Failed {
		t.Errorf("failing command not reported: %+v", results[0])
	}
	if results[0].Stderr == "" {
		t.Errorf("stderr not captured: %+v", results[0])
	}
}

func TestApplyCommandTimeout(t *testing.T) {
	conn := startAgent(t, Options{})
	results := callApply(t, conn, proto.ApplyParams{
		Ops: []proto.Op{{
			OpType: proto.OpTypeCommand,
			Command: &proto.CommandOp{
				Shell:   "sleep 5",
				Timeout: 200, // ms
			},
		}},
	})
	if !results[0].Failed {
		t.Errorf("timed-out command not failed: %+v", results[0])
	}
}

func TestApplyServiceWithFakeRunner(t *testing.T) {
	fake := &fakeService{enabled: map[string]bool{"nginx": false}, state: map[string]string{"nginx": "inactive"}}
	conn := startAgent(t, Options{Services: fake})

	enabled := true
	results := callApply(t, conn, proto.ApplyParams{
		Ops: []proto.Op{{
			OpType:  proto.OpTypeService,
			Service: &proto.ServiceOp{Unit: "nginx", State: proto.StateStarted, Enabled: &enabled},
		}},
	})
	if results[0].Failed {
		t.Fatalf("service apply failed: %+v", results[0])
	}
	if !results[0].Changed {
		t.Errorf("service apply not changed: %+v", results[0])
	}
	if !fake.enabled["nginx"] || fake.state["nginx"] != "active" {
		t.Errorf("fake state = enabled:%v state:%v, want enabled/active", fake.enabled["nginx"], fake.state["nginx"])
	}

	// Idempotence: second apply reports no change.
	results = callApply(t, conn, proto.ApplyParams{
		Ops: []proto.Op{{
			OpType:  proto.OpTypeService,
			Service: &proto.ServiceOp{Unit: "nginx", State: proto.StateStarted, Enabled: &enabled},
		}},
	})
	if results[0].Changed {
		t.Errorf("second service apply changed: %+v", results[0])
	}
}

func TestApplyServiceCheckMode(t *testing.T) {
	fake := &fakeService{enabled: map[string]bool{}, state: map[string]string{"nginx": "inactive"}}
	conn := startAgent(t, Options{Services: fake})

	results := callApply(t, conn, proto.ApplyParams{
		Check: true,
		Ops: []proto.Op{{
			OpType:  proto.OpTypeService,
			Service: &proto.ServiceOp{Unit: "nginx", State: proto.StateStarted},
		}},
	})
	if !results[0].Changed {
		t.Errorf("check mode did not report would-change: %+v", results[0])
	}
	if fake.state["nginx"] == "active" {
		t.Errorf("check mode mutated service state")
	}
}

func TestApplyServiceInvalidState(t *testing.T) {
	conn := startAgent(t, Options{Services: &fakeService{}})
	results := callApply(t, conn, proto.ApplyParams{
		Ops: []proto.Op{{
			OpType:  proto.OpTypeService,
			Service: &proto.ServiceOp{Unit: "nginx", State: "wonky"},
		}},
	})
	if !results[0].Failed {
		t.Errorf("invalid state accepted: %+v", results[0])
	}
}

func TestApplyMalformedOp(t *testing.T) {
	conn := startAgent(t, Options{})
	results := callApply(t, conn, proto.ApplyParams{
		Ops: []proto.Op{{OpType: "bogus"}},
	})
	if !results[0].Failed {
		t.Errorf("malformed op not failed: %+v", results[0])
	}
	if results[1].Summary && results[1].Failures != 1 {
		t.Errorf("summary failures = %d, want 1", results[1].Failures)
	}
}

func TestExecMethod(t *testing.T) {
	conn := startAgent(t, Options{})
	var res proto.ExecResult
	rpcErr, err := conn.Call(proto.Request{
		ID:     "e1",
		Method: proto.MethodExec,
		Params: mustMarshal(proto.ExecParams{Shell: "echo hello"}),
	}, &res)
	if err != nil || rpcErr != nil {
		t.Fatalf("Exec: err=%v rpcErr=%v", err, rpcErr)
	}
	if res.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", res.ExitCode)
	}
	if trimSpace(res.Stdout) != "hello" {
		t.Errorf("stdout = %q, want hello", res.Stdout)
	}
}

func TestGetPutFile(t *testing.T) {
	conn := startAgent(t, Options{})
	path := filepath.Join(t.TempDir(), "served.txt")

	rpcErr, err := conn.Call(proto.Request{
		ID:     "w1",
		Method: proto.MethodPutFile,
		Params: mustMarshal(proto.FileParams{Path: path, Content: []byte("data"), Mode: "0600"}),
	}, nil)
	if err != nil || rpcErr != nil {
		t.Fatalf("PutFile: err=%v rpcErr=%v", err, rpcErr)
	}

	var info proto.FileInfo
	rpcErr, err = conn.Call(proto.Request{
		ID:     "r1",
		Method: proto.MethodGetFile,
		Params: mustMarshal(proto.FileParams{Path: path}),
	}, &info)
	if err != nil || rpcErr != nil {
		t.Fatalf("GetFile: err=%v rpcErr=%v", err, rpcErr)
	}
	if string(info.Content) != "data" || info.Mode != "0600" {
		t.Errorf("GetFile = %+v", info)
	}
}

func TestUnknownMethod(t *testing.T) {
	conn := startAgent(t, Options{})
	rpcErr, err := conn.Call(proto.Request{ID: "u1", Method: "Nope"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rpcErr == nil || rpcErr.Code != proto.CodeUnsupported {
		t.Fatalf("rpcErr = %v, want unsupported", rpcErr)
	}
}

// fakeService is an in-memory ServiceRunner for tests.
type fakeService struct {
	mu      sync.Mutex
	enabled map[string]bool
	state   map[string]string
}

func (f *fakeService) IsEnabled(_ context.Context, unit string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.enabled[unit], nil
}

func (f *fakeService) State(_ context.Context, unit string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.state[unit]
	if !ok {
		return "inactive", nil
	}
	return s, nil
}

func (f *fakeService) Enable(_ context.Context, unit string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enabled[unit] = true
	return nil
}

func (f *fakeService) Disable(_ context.Context, unit string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enabled[unit] = false
	return nil
}

func (f *fakeService) Start(_ context.Context, unit string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state[unit] = "active"
	return nil
}

func (f *fakeService) Stop(_ context.Context, unit string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state[unit] = "inactive"
	return nil
}

func (f *fakeService) Restart(_ context.Context, unit string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state[unit] = "active"
	return nil
}

func (f *fakeService) Reload(_ context.Context, unit string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state[unit] = "active"
	return nil
}

func mustMarshal(v any) json.RawMessage {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return raw
}
