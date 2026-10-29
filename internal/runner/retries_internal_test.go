package runner

import (
	"context"
	"crypto/x509"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/claymod/claymod/internal/proto"
)

// TestDialWithRetriesRecoversTransiently: two connection failures then
// success — the third attempt must connect and report 3 dials.
func TestDialWithRetriesRecoversTransiently(t *testing.T) {
	calls := atomic.Int32{}
	old := dialFn
	dialFn = func(addr, serverName string, id proto.Identity, pool *x509.CertPool) (*proto.Conn, error) {
		if calls.Add(1) <= 2 {
			return nil, errors.New("transient: connection refused")
		}
		return &proto.Conn{}, nil // stub: never used beyond return
	}
	t.Cleanup(func() { dialFn = old })

	spec := HostSpec{Target: Target{Hostname: "web01", Addr: "127.0.0.1:1", ServerName: "web01"}}
	conn, err := dialWithRetries(context.Background(), spec, Request{}, Options{DialRetries: 5})
	if err != nil {
		t.Fatalf("dialWithRetries gave up: %v", err)
	}
	if conn == nil {
		t.Fatal("nil conn on success")
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("dial calls = %d, want 3", got)
	}
}

// TestDialWithRetriesExhaustsAndReports: permanent failure reports the
// attempt count and the last error.
func TestDialWithRetriesExhaustsAndReports(t *testing.T) {
	calls := atomic.Int32{}
	old := dialFn
	dialFn = func(addr, serverName string, id proto.Identity, pool *x509.CertPool) (*proto.Conn, error) {
		calls.Add(1)
		return nil, errors.New("connection refused")
	}
	t.Cleanup(func() { dialFn = old })

	spec := HostSpec{Target: Target{Hostname: "web01", Addr: "127.0.0.1:1", ServerName: "web01"}}
	_, err := dialWithRetries(context.Background(), spec, Request{}, Options{DialRetries: 2})
	if err == nil {
		t.Fatal("dialWithRetries succeeded on a dead host")
	}
	if got := calls.Load(); got != 3 { // 1 + 2 retries
		t.Errorf("dial calls = %d, want 3", got)
	}
	if !strings.Contains(err.Error(), "after 3 attempt") {
		t.Errorf("err = %v, want attempt count", err)
	}
}

// TestDialWithRetriesHonorsContext: a cancelled context stops the retry
// loop promptly instead of sleeping through the backoff.
func TestDialWithRetriesHonorsContext(t *testing.T) {
	old := dialFn
	dialFn = func(addr, serverName string, id proto.Identity, pool *x509.CertPool) (*proto.Conn, error) {
		return nil, errors.New("down")
	}
	t.Cleanup(func() { dialFn = old })

	ctx, cancel := context.WithCancel(context.Background())
	spec := HostSpec{Target: Target{Hostname: "web01", Addr: "127.0.0.1:1", ServerName: "web01"}}
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	_, err := dialWithRetries(ctx, spec, Request{}, Options{DialRetries: 10})
	if err == nil {
		t.Fatal("dialWithRetries ignored cancellation")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("cancellation took %v; retry loop slept through it", elapsed)
	}
}

// TestDialWithRetriesZeroDisables: DialRetries=0 means dial ONCE — the
// documented disable (the old code mapped 0 to the default 3).
func TestDialWithRetriesZeroDisables(t *testing.T) {
	calls := atomic.Int32{}
	old := dialFn
	dialFn = func(addr, serverName string, id proto.Identity, pool *x509.CertPool) (*proto.Conn, error) {
		calls.Add(1)
		return nil, errors.New("down")
	}
	t.Cleanup(func() { dialFn = old })

	spec := HostSpec{Target: Target{Hostname: "web01", Addr: "127.0.0.1:1", ServerName: "web01"}}
	_, err := dialWithRetries(context.Background(), spec, Request{}, Options{DialRetries: 0})
	if err == nil {
		t.Fatal("expected failure")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("dial calls = %d, want 1 (0 must disable retries)", got)
	}
}

// TestDialBackoffStaysBounded: the doubling must never overflow into a
// negative Duration (which would panic rand.Int63n) and never exceed
// the cap — exercised across the shift-overflow range.
func TestDialBackoffStaysBounded(t *testing.T) {
	for try := 1; try <= 64; try++ {
		b := dialBackoff(try)
		if b <= 0 {
			t.Fatalf("dialBackoff(%d) = %v, must be positive", try, b)
		}
		if b > dialBackoffCap {
			t.Fatalf("dialBackoff(%d) = %v > cap %v", try, b, dialBackoffCap)
		}
	}
	// The growth is real before the cap: try=1 base, try=2 double.
	if dialBackoff(1) != dialBackoffBase || dialBackoff(2) != 2*dialBackoffBase {
		t.Errorf("backoff growth wrong: %v %v", dialBackoff(1), dialBackoff(2))
	}
}
