package proto

import (
	"net"
	"testing"
	"time"
)

// TestHandshakeDeadlineEnforced checks that a peer which completes the TLS
// handshake but then goes silent cannot hold the protocol handshake open
// past defaultHandshakeFrame — the bug where Send/Recv overwrote the
// handshake deadline made this wait for the 60s frame timeout instead.
func TestHandshakeDeadlineEnforced(t *testing.T) {
	_, serverID, clientID, pool := makeTestCA(t)

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
		conn, err := Server(raw, DefaultFrameTimeout)
		if conn != nil {
			conn.Close()
		}
		errCh <- err
	}()

	// Raw TLS client: complete the TLS handshake, then send nothing.
	raw, err := dialTestTLS(t, ln.Addr().String(), clientID, pool)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	start := time.Now()
	select {
	case err := <-errCh:
		elapsed := time.Since(start)
		if err == nil {
			t.Fatal("server handshake succeeded against a silent peer")
		}
		// Must fail near defaultHandshakeFrame (5s), not the 60s frame
		// timeout. Allow generous slack for CI slowness but stay well
		// under the frame timeout.
		if elapsed > 20*time.Second {
			t.Fatalf("handshake took %v, want ~%v (deadline not enforced)",
				elapsed, defaultHandshakeFrame)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("server handshake never timed out")
	}
}

// TestPeerCommonNameForcesHandshake checks that PeerCommonName works on a
// freshly accepted TLS conn that has done no application I/O (where the
// TLS handshake is still lazy).
func TestPeerCommonNameForcesHandshake(t *testing.T) {
	_, serverID, clientID, pool := makeTestCA(t)

	ln, err := Listen("127.0.0.1:0", serverID, pool)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type result struct {
		cn  string
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			resCh <- result{"", err}
			return
		}
		// No protocol I/O at all: query the CN straight from Accept.
		cn, err := PeerCommonName(raw)
		resCh <- result{cn, err}
		raw.Close()
	}()

	raw, err := dialTestTLS(t, ln.Addr().String(), clientID, pool)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	select {
	case res := <-resCh:
		if res.err != nil {
			t.Fatalf("PeerCommonName returned error: %v", res.err)
		}
		if res.cn != "web01" {
			t.Errorf("PeerCommonName = %q, want web01", res.cn)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("PeerCommonName never returned")
	}
}

// TestPeerCommonNameNonTLS checks the error path for raw connections.
func TestPeerCommonNameNonTLS(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	if _, err := PeerCommonName(c2); err == nil {
		t.Fatal("PeerCommonName accepted a non-TLS connection")
	}
}
