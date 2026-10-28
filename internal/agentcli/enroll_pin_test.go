package agentcli

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/claymod/claymod/internal/ca"
)

// spinCA serves /ca.pem (plus a dummy /enroll) over TLS with a throwaway
// CA — exactly what a real control server exposes to a pinning client.
func spinCA(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	authority, err := ca.New("pin-test-ca")
	if err != nil {
		t.Fatal(err)
	}
	// httptest serves on 127.0.0.1: the leaf needs an IP SAN for the
	// enrollment call's real hostname verification to pass.
	leafPEM, keyPEM, err := authority.IssueCert(ca.IssueOptions{
		CommonName:  "control.test",
		Usage:       ca.UsageServer,
		DNSNames:    []string{"control.test"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
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
	return ts, hex.EncodeToString(sum[:])
}

func TestPinnedDownloadClientAcceptsCorrectCA(t *testing.T) {
	ts, pin := spinCA(t)
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

func TestPinnedDownloadClientRejectsWrongCA(t *testing.T) {
	ts, _ := spinCA(t)
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
