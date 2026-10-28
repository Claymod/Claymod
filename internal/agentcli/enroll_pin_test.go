package agentcli

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/claymod/claymod/internal/ca"
	"github.com/claymod/claymod/internal/enroll"
)

// spinCA serves /ca.pem (plus a dummy /enroll) over TLS with a throwaway
// CA — exactly what a real control server exposes to a pinning client.
func spinCA(t *testing.T) (*httptest.Server, string, []byte) {
	t.Helper()
	authority, err := ca.New("pin-test-ca")
	if err != nil {
		t.Fatal(err)
	}
	// The leaf carries ONLY DNS SANs, exactly like a real bootstrap
	// certificate (--server-name, no IP SAN). httptest serves on
	// 127.0.0.1 — bare-IP enrollment must still work through the pinned
	// client (the pin is the identity; hostname checks are waived there).
	leafPEM, keyPEM, err := authority.IssueCert(ca.IssueOptions{
		CommonName: "control.test",
		Usage:      ca.UsageServer,
		DNSNames:   []string{"control.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(leafPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ca.pem", func(w http.ResponseWriter, r *http.Request) {
		w.Write(authority.CertPEM())
	})
	mux.HandleFunc("/enroll", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"hostname":"web01","wg_ip":"10.42.0.2"}`))
	})
	ts := httptest.NewUnstartedServer(mux)
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	ts.StartTLS()
	t.Cleanup(ts.Close)

	block, _ := pem.Decode(authority.CertPEM())
	sum := sha256.Sum256(block.Bytes)
	return ts, hex.EncodeToString(sum[:]), authority.CertPEM()
}

// TestTokenOnlyModeAcceptsAnyServer: --insecure-token-only skips all
// server authentication (no CA, no pin): the one-time token is the sole
// credential, so any server certificate is accepted — including a
// bare-IP target with a DNS-SAN-only cert, the /enroll.sh flow.
func TestTokenOnlyModeAcceptsAnyServer(t *testing.T) {
	ts, _, _ := spinCA(t)
	cmd := NewEnrollCmd()
	cmd.SetContext(context.Background())
	if err := runEnroll(cmd, enrollOptions{
		serverURL: ts.URL,
		token:     "tok",
		hostname:  "web01",
		tokenOnly: true,
		outDir:    t.TempDir(),
	}); err != nil {
		t.Fatalf("token-only enrollment failed: %v", err)
	}
}

// TestTokenOnlyModeMutuallyExclusive: the trust modes are exclusive.
func TestTokenOnlyModeMutuallyExclusive(t *testing.T) {
	if err := runEnroll(NewEnrollCmd(), enrollOptions{
		serverURL: "https://control.test:8443",
		token:     "tok",
		hostname:  "web01",
		tokenOnly: true,
		caPin:     strings.Repeat("ab", 32),
		outDir:    t.TempDir(),
	}); err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("err = %v, want --insecure-token-only/--ca-pin conflict", err)
	}
	if err := runEnroll(NewEnrollCmd(), enrollOptions{
		serverURL: "https://control.test:8443",
		token:     "tok",
		hostname:  "web01",
		outDir:    t.TempDir(),
	}); err == nil || !strings.Contains(err.Error(), "exactly one trust mode") {
		t.Fatalf("err = %v, want no-trust-mode refusal", err)
	}
}

func TestPinnedDownloadClientAcceptsCorrectCA(t *testing.T) {
	ts, pin, _ := spinCA(t)
	client, err := newPinnedDownloadClient(ts.URL, pin)
	if err != nil {
		t.Fatalf("newPinnedDownloadClient rejected the correct CA pin: %v", err)
	}
	resp, err := client.Get(ts.URL + "/enroll")
	if err != nil {
		t.Fatalf("enrollment call through the verified client failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// TestPinnedDownloadAllowsBareIP: the pinned client connects to
// https://127.0.0.1:<port> against a DNS-SAN-only certificate — the
// documented homelab flow (enroll via bare IP, cert has --server-name
// DNS SANs only). The pin is the identity, so hostname checks are
// waived; the chain must still verify against the pinned CA.
func TestPinnedDownloadAllowsBareIP(t *testing.T) {
	ts, pin, _ := spinCA(t)
	client, err := newPinnedDownloadClient(ts.URL, pin)
	if err != nil {
		t.Fatalf("newPinnedDownloadClient: %v", err)
	}
	resp, err := client.Get(ts.URL + "/enroll")
	if err != nil {
		t.Fatalf("bare-IP enrollment through the pinned client failed: %v", err)
	}
	resp.Body.Close()
}

// TestCAPinnedClientKeepsHostnameCheck: the --ca path (stock
// verification) still REQUIRES the hostname to match — the asymmetry is
// deliberate: --ca trusts a bundle and verifies names; --ca-pin trusts a
// single identity and waives names.
func TestCAPinnedClientKeepsHostnameCheck(t *testing.T) {
	ts, _, caPEM := spinCA(t)
	// The --ca path (stock verification) with the CORRECT bundle.
	client, err := enroll.NewPinnedClient(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	// Bare IP vs DNS-SAN-only cert: stock verification must reject —
	// the asymmetry with --ca-pin is deliberate.
	if _, err := client.Get(ts.URL + "/enroll"); err == nil {
		t.Fatal("stock --ca client accepted a bare-IP connection without a matching SAN")
	}
}

func TestPinnedDownloadClientRejectsWrongCA(t *testing.T) {
	ts, _, _ := spinCA(t)
	wrong := strings.Repeat("ab", 32)
	_, err := newPinnedDownloadClient(ts.URL, wrong)
	if err == nil {
		t.Fatal("client accepted a wrong CA pin")
	}
	if !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Errorf("error = %q, want fingerprint mismatch", err.Error())
	}
}

func TestPinnedDownloadClientRejectsTamperedCA(t *testing.T) {
	// A server serving a CA whose digest does not match the pin (e.g. a
	// MITM with its own CA) must be refused before anything is trusted.
	authority, err := ca.New("rogue-ca")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ca.pem", func(w http.ResponseWriter, r *http.Request) {
		w.Write(authority.CertPEM())
	})
	ts := httptest.NewServer(mux) // plain HTTP is fine: the pin is the trust
	defer ts.Close()

	honest, err := ca.New("honest-ca")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(honest.CertPEM())
	sum := sha256.Sum256(block.Bytes)

	_, err = newPinnedDownloadClient(ts.URL, hex.EncodeToString(sum[:]))
	if err == nil {
		t.Fatal("client accepted a tampered /ca.pem")
	}
	if !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Errorf("error = %q, want fingerprint mismatch", err.Error())
	}
}

// TestPinnedDownloadClientIgnoresAppendedCerts: a MITM serving
// [pinned CA][rogue CA] must NOT get the rogue trusted as a root. The
// TLS server is issued by the rogue CA; with bundle-trust the call
// would succeed — with pinned-block trust it must fail.
func TestPinnedDownloadClientIgnoresAppendedCerts(t *testing.T) {
	honest, err := ca.New("honest-ca")
	if err != nil {
		t.Fatal(err)
	}
	rogue, err := ca.New("rogue-ca")
	if err != nil {
		t.Fatal(err)
	}
	// The server presents a leaf issued by the ROGUE CA.
	leafPEM, keyPEM, err := rogue.IssueCert(ca.IssueOptions{
		CommonName: "evil.test",
		Usage:      ca.UsageServer,
		DNSNames:   []string{"evil.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(leafPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	// ...but serves a bundle that APPENDS the honest CA first.
	bundle := append(append([]byte{}, honest.CertPEM()...), rogue.CertPEM()...)
	mux := http.NewServeMux()
	mux.HandleFunc("/ca.pem", func(w http.ResponseWriter, r *http.Request) {
		w.Write(bundle)
	})
	mux.HandleFunc("/enroll", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	})
	ts := httptest.NewUnstartedServer(mux)
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	ts.StartTLS()
	defer ts.Close()

	block, _ := pem.Decode(honest.CertPEM())
	sum := sha256.Sum256(block.Bytes)
	pin := hex.EncodeToString(sum[:])

	client, err := newPinnedDownloadClient(ts.URL, pin)
	if err != nil {
		t.Fatalf("pinned client rejected correct first cert: %v", err)
	}
	// The enrollment call must fail TLS verification: the rogue CA
	// appended after the pinned block must not be a trust root.
	resp, err := client.Get(ts.URL + "/enroll")
	if err == nil {
		resp.Body.Close()
		t.Fatal("enrollment succeeded through a rogue CA appended to the bundle")
	}
}
