package enrollserver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testPin = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// newScriptServer spins a server with a CA (so /ca.pem works).
func newScriptServer(t *testing.T) *Server {
	t.Helper()
	s := newTestServer(t)
	return &Server{Inv: s.Inv, CA: s.CA, WG: s.WG}
}

func fetchScript(t *testing.T, ts *httptest.Server, method, path, body string) (int, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, ts.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

func TestEnrollScriptEmbedsPinAndFlow(t *testing.T) {
	s := newScriptServer(t)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	status, script := fetchScript(t, ts, "POST", "/enroll.sh", testPin)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	for _, want := range []string{
		testPin,                      // pinned CA fingerprint
		"claymod-agent.service",      // systemd unit
		"WantedBy=multi-user.target", // enabled for boot
		"systemctl enable --now",     // started now + persistent
		"agent.sha256",               // agent digest check
		"digest mismatch",            // fail-closed on tamper
		"fingerprint mismatch",       // fail-closed on wrong CA
		"set -eu",                    // strict mode
		"wg-setup",                   // WireGuard bring-up
		"--token \"$TOKEN\"",         // token passed at runtime
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script missing %q", want)
		}
	}
}

func TestEnrollScriptPinValidation(t *testing.T) {
	s := newScriptServer(t)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	for _, body := range []string{"not-a-pin", "pin=zz", strings.Repeat("ab", 33)} {
		status, _ := fetchScript(t, ts, "POST", "/enroll.sh", body)
		if status != http.StatusBadRequest {
			t.Errorf("body %q: status = %d, want 400", body, status)
		}
	}
	// GET with ?pin= works too, same validation.
	status, script := fetchScript(t, ts, "GET", "/enroll.sh?pin="+testPin, "")
	if status != http.StatusOK || !strings.Contains(script, testPin) {
		t.Errorf("GET ?pin: status = %d", status)
	}
}

func TestEnrollScriptNeverEmbedsTokens(t *testing.T) {
	s := newScriptServer(t)
	if err := s.Inv.StoreToken("super-secret-token", "web01", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	_, script := fetchScript(t, ts, "POST", "/enroll.sh", testPin)
	if strings.Contains(script, "super-secret-token") {
		t.Fatal("served script embeds an enrollment token")
	}
	if !strings.Contains(script, "missing --token") {
		t.Error("script should require the token at run time")
	}
}

func TestEnrollScriptShSyntax(t *testing.T) {
	s := newScriptServer(t)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	_, script := fetchScript(t, ts, "POST", "/enroll.sh", testPin)

	path := filepath.Join(t.TempDir(), "enroll.sh")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("sh", "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("sh -n rejected the served script: %v\n%s", err, out)
	}
}

func TestCAServeAndDigest(t *testing.T) {
	s := newScriptServer(t)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	caPEM, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(caPEM), "BEGIN CERTIFICATE") {
		t.Fatal("/ca.pem did not serve a PEM certificate")
	}
	// The pin the operator publishes is the SHA-256 of this certificate's DER.
	block, _ := pem.Decode(caPEM)
	if block == nil {
		t.Fatal("no PEM block in /ca.pem")
	}
	sum := sha256.Sum256(block.Bytes)
	t.Logf("ca fingerprint: %s", hex.EncodeToString(sum[:]))
}
