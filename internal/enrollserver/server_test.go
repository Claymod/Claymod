package enroll

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/claymod/claymod/internal/ca"
	"github.com/claymod/claymod/internal/inventory"
	"github.com/claymod/claymod/internal/proto"
	"github.com/claymod/claymod/internal/wgmgr"
)

// testServer spins up a real HTTPS bootstrap server with a throwaway CA
// and fake WG backend, and returns the server URL plus helpers.
type testServer struct {
	URL    string
	Inv    *inventory.Inventory
	CA     *ca.CA
	WG     *wgmgr.Manager
	Enroll *Server
	client *http.Client
	t      *testing.T
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()
	authority, err := ca.New("enroll-test-ca")
	if err != nil {
		t.Fatal(err)
	}
	// httptest.StartTLS listens on 127.0.0.1, so the client verifies the
	// certificate against the loopback IP: it needs an IP SAN.
	serverPEM, serverKey, err := authority.IssueCert(ca.IssueOptions{
		CommonName:  "bootstrap.test",
		Usage:       ca.UsageServer,
		DNSNames:    []string{"bootstrap.test", "localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	})
	if err != nil {
		t.Fatal(err)
	}
	serverID, err := proto.LoadIdentity(serverPEM, serverKey)
	if err != nil {
		t.Fatal(err)
	}

	inv, err := inventory.Open(filepath.Join(t.TempDir(), "inventory.db"), "10.42.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { inv.Close() })

	wg, err := wgmgr.New("claymod0", wgmgr.NewFakeBackend(), "127.0.0.1:51821")
	if err != nil {
		t.Fatal(err)
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	enrollSrv := NewServer(inv, authority, wg, log)

	// Real TLS: the handler runs behind the CA-issued server certificate.
	ts := httptest.NewUnstartedServer(enrollSrv.Handler())
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverID.Certificate},
		MinVersion:   tls.VersionTLS13,
	}
	ts.StartTLS()
	t.Cleanup(ts.Close)

	client, err := NewPinnedClient(authority.CertPEM())
	if err != nil {
		t.Fatal(err)
	}
	return &testServer{
		URL:    ts.URL,
		Inv:    inv,
		CA:     authority,
		WG:     wg,
		Enroll: enrollSrv,
		client: client,
		t:      t,
	}
}

// enroll is a client-side enrollment call using a fresh WG key pair.
func (s *testServer) enroll(token, hostname string) (*Response, error) {
	s.t.Helper()
	keys, err := wgmgr.GenerateKeyPair()
	if err != nil {
		s.t.Fatal(err)
	}
	return EnrollClient(context.Background(), s.URL, s.client, Request{
		Token:       token,
		Hostname:    hostname,
		WgPublicKey: keys.Public,
	})
}

func TestEnrollHappyPath(t *testing.T) {
	s := newTestServer(t)
	if err := s.Inv.StoreToken("tok1", "web01", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	resp, err := s.enroll("tok1", "web01")
	if err != nil {
		t.Fatalf("enroll returned error: %v", err)
	}
	if resp.Hostname != "web01" || resp.WGIP != "10.42.0.2" {
		t.Errorf("response = %+v", resp)
	}
	if len(resp.ClientCert) == 0 || len(resp.ClientKey) == 0 || len(resp.CACert) == 0 {
		t.Errorf("response missing cert material: %+v", resp)
	}
	if resp.WgServerPublicKey != s.WG.ControlKeys.Public {
		t.Errorf("WgServerPublicKey = %q, want %q", resp.WgServerPublicKey, s.WG.ControlKeys.Public)
	}
	if resp.Overlay != "10.42.0.0/24" {
		t.Errorf("Overlay = %q, want 10.42.0.0/24 (the aggregate for the agent's peer)", resp.Overlay)
	}

	// The issued certificate must verify for the hostname the runner
	// will use as TLS ServerName (DNS SAN, not just CN), and must be a
	// SERVER certificate: the agent listens, the control server dials.
	issued, err := ca.ParseCertPEM(resp.ClientCert)
	if err != nil {
		t.Fatal(err)
	}
	if err := issued.VerifyHostname("web01"); err != nil {
		t.Errorf("issued cert does not verify for hostname web01: %v", err)
	}
	if len(issued.ExtKeyUsage) != 1 || issued.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("issued cert EKU = %v, want [ServerAuth] (agent is the TLS server)",
			issued.ExtKeyUsage)
	}

	// The host is registered with its WG key and issued cert.
	host, err := s.Inv.GetHost("web01")
	if err != nil {
		t.Fatal(err)
	}
	if host.PublicKey == "" || host.CertPEM == "" {
		t.Errorf("host row incomplete: %+v", host)
	}
	// The WG peer exists on the overlay.
	peers, err := s.WG.Peers()
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 {
		t.Fatalf("peers = %+v, want 1", peers)
	}
	if peers[0].AllowedIPs != "10.42.0.2/32" {
		t.Errorf("peer AllowedIPs = %q", peers[0].AllowedIPs)
	}
}

func TestEnrollTokenIsSingleUse(t *testing.T) {
	s := newTestServer(t)
	if err := s.Inv.StoreToken("tok1", "web01", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.enroll("tok1", "web01"); err != nil {
		t.Fatal(err)
	}
	_, err := s.enroll("tok1", "web01")
	if err == nil {
		t.Fatal("second enrollment with the same token succeeded")
	}
	if !strings.Contains(err.Error(), "already used") && !strings.Contains(err.Error(), "401") {
		t.Errorf("error = %v, want token-used refusal", err)
	}
}

func TestEnrollRejectsBadToken(t *testing.T) {
	s := newTestServer(t)
	_, err := s.enroll("ghost", "web01")
	if err == nil {
		t.Fatal("enrollment accepted an unknown token")
	}
}

func TestEnrollRejectsExpiredToken(t *testing.T) {
	s := newTestServer(t)
	if err := s.Inv.StoreToken("tok1", "web01", time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	_, err := s.enroll("tok1", "web01")
	if err == nil {
		t.Fatal("enrollment accepted an expired token")
	}
}

func TestEnrollRejectsHostnameMismatch(t *testing.T) {
	s := newTestServer(t)
	if err := s.Inv.StoreToken("tok1", "web01", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	_, err := s.enroll("tok1", "web99")
	if err == nil {
		t.Fatal("enrollment accepted a hostname mismatch")
	}
	// The token must survive a mismatched attempt.
	if _, err := s.Inv.ValidateToken("tok1"); err != nil {
		t.Errorf("token burned by mismatched attempt: %v", err)
	}
}

func TestEnrollClientRejectsUntrustedServer(t *testing.T) {
	s := newTestServer(t)
	// Client verifying against a different CA must refuse the TLS
	// handshake (the certificate is never even sent).
	rogue, err := ca.New("rogue")
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewPinnedClient(rogue.CertPEM())
	if err != nil {
		t.Fatal(err)
	}
	_, err = EnrollClient(context.Background(), s.URL, client, Request{
		Token: "tok1", Hostname: "web01", WgPublicKey: "pk",
	})
	if err == nil {
		t.Fatal("enrollment succeeded against an untrusted server")
	}
}

func TestRevokeLifecycle(t *testing.T) {
	s := newTestServer(t)
	if err := s.Inv.StoreToken("tok1", "web01", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	resp, err := s.enroll("tok1", "web01")
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Enroll.Revoke("web01"); err != nil {
		t.Fatalf("Revoke returned error: %v", err)
	}
	// Host row gone, IP freed.
	if _, err := s.Inv.GetHost("web01"); !errors.Is(err, inventory.ErrNotFound) {
		t.Errorf("host still exists after revoke: %v", err)
	}
	// WG peer removed.
	peers, err := s.WG.Peers()
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 0 {
		t.Errorf("peers after revoke = %+v, want none", peers)
	}
	// Certificate serial revoked (CRL-lite).
	cert, err := ca.ParseCertPEM(resp.ClientCert)
	if err != nil {
		t.Fatal(err)
	}
	if revoked, err := s.Inv.IsRevoked(cert.SerialNumber.String()); err != nil || !revoked {
		t.Errorf("IsRevoked = %v, %v; want true", revoked, err)
	}
}

func TestNewPinnedClientRejectsEmptyBundle(t *testing.T) {
	if _, err := NewPinnedClient([]byte("not a cert")); err == nil {
		t.Fatal("NewPinnedClient accepted a garbage bundle")
	}
}

// TestFingerprintPinning verifies a client pinning the exact server
// certificate fingerprint accepts the right server and refuses any other.
func TestFingerprintPinning(t *testing.T) {
	s := newTestServer(t)
	for _, tok := range []struct{ token, host string }{
		{"tok1", "web01"}, {"tok2", "web02"},
	} {
		if err := s.Inv.StoreToken(tok.token, tok.host, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}

	// Fingerprint of the server's leaf certificate (SHA-256 of its DER).
	der := mustReadCert(t, s)
	sum := sha256.Sum256(der)
	fingerprint := hex.EncodeToString(sum[:])

	// A client pinning exactly this fingerprint connects fine.
	pinned := newFingerprintClient(t, fingerprint)
	resp, err := EnrollClient(context.Background(), s.URL, pinned, Request{
		Token: "tok1", Hostname: "web01", WgPublicKey: "pk",
	})
	if err != nil {
		t.Fatalf("pinned enroll returned error: %v", err)
	}
	if resp.Hostname != "web01" {
		t.Errorf("resp = %+v", resp)
	}

	// A client pinning a wrong fingerprint is refused.
	wrong := newFingerprintClient(t, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	_, err = EnrollClient(context.Background(), s.URL, wrong, Request{
		Token: "tok2", Hostname: "web02", WgPublicKey: "pk",
	})
	if err == nil {
		t.Fatal("fingerprint-pinned client accepted the wrong server")
	}
}

// mustReadCert returns the server's PEM certificate (from the test
// server's TLS config).
// mustReadCert returns the server's leaf certificate as raw DER (the
// exact bytes fingerprint pinning hashes), fetched over a real TLS
// handshake.
func mustReadCert(t *testing.T, s *testServer) []byte {
	t.Helper()
	pool := s.CA.Pool()
	conn, err := tls.Dial("tcp", stripScheme(s.URL), &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("no peer certificates")
	}
	return state.PeerCertificates[0].Raw
}

// newFingerprintClient builds a client that pins a SHA-256 fingerprint.
func newFingerprintClient(t *testing.T, wantFingerprint string) *http.Client {
	t.Helper()
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				// InsecureSkipVerify is paired with the fingerprint check
				// below: the peer is authenticated by pinning, not by a
				// CA chain.
				InsecureSkipVerify: true,
				VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
					if len(rawCerts) == 0 {
						return errors.New("no server certificate")
					}
					sum := sha256.Sum256(rawCerts[0])
					if hex.EncodeToString(sum[:]) != wantFingerprint {
						return errors.New("server certificate fingerprint mismatch")
					}
					return nil
				},
			},
		},
	}
}

func stripScheme(url string) string {
	for _, prefix := range []string{"https://", "http://"} {
		if len(url) > len(prefix) && url[:len(prefix)] == prefix {
			return url[len(prefix):]
		}
	}
	return url
}
