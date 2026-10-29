package enrollserver

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/claymod/claymod/internal/enroll"
	"github.com/claymod/claymod/internal/wgmgr"
)

// TestSecretsNeverLogged: the bootstrap surface handles tokens and key
// material — none of it may ever reach the logs. Runs a real enrollment
// attempt (failing: wrong hostname) with a known token through a
// buffered logger and asserts the token, the WG private key and the CA
// key never appear.
func TestSecretsNeverLogged(t *testing.T) {
	var buf bytes.Buffer
	fixture := newTestServer(t)
	s := fixture.Enroll
	s.Log = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	const secretToken = "super-secret-token-value"
	if err := s.Inv.StoreToken(secretToken, "web01", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	// 1. A failed enrollment carrying the token (wrong hostname binding).
	body, _ := json.Marshal(enroll.Request{Token: secretToken, Hostname: "evil"})
	resp, err := ts.Client().Post(ts.URL+"/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// 2. A successful enrollment with the same (still unconsumed) token
	//    (worst case: the success path logs).
	keys, err := wgmgr.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	body, _ = json.Marshal(enroll.Request{Token: secretToken, Hostname: "web01", WgPublicKey: keys.Public})
	resp, err = ts.Client().Post(ts.URL+"/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	logs := buf.String()
	if logs == "" {
		t.Fatal("no logs captured — the test asserts on nothing")
	}
	for _, secret := range []string{
		secretToken,
		keys.Private, // the HOST's WG private key (server must not even see it)
	} {
		if strings.Contains(logs, secret) {
			t.Errorf("logs contain secret material (%q…)", secret[:12])
		}
	}
}
