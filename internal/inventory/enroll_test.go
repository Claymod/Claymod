package inventory

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func enrollTestInv(t *testing.T) *Inventory {
	t.Helper()
	path := filepath.Join(t.TempDir(), "inventory.db")
	inv, err := Open(path, "10.42.0.0/24")
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	t.Cleanup(func() { inv.Close() })
	return inv
}

func mustToken(t *testing.T, inv *Inventory, token, hostname string, ttl time.Duration) {
	t.Helper()
	if err := inv.StoreToken(token, hostname, time.Now().Add(ttl)); err != nil {
		t.Fatal(err)
	}
}

func TestEnrollHostHappyPath(t *testing.T) {
	inv := enrollTestInv(t)
	mustToken(t, inv, "tok1", "web01", time.Hour)

	h, err := inv.EnrollHost("tok1", "web01", "pk-abc", "pem-abc")
	if err != nil {
		t.Fatalf("EnrollHost returned error: %v", err)
	}
	// .1 is reserved for the control server: hosts start at .2.
	if h.WGIP != "10.42.0.2" {
		t.Errorf("WGIP = %q, want 10.42.0.2 (.1 is the server's)", h.WGIP)
	}
	if h.PublicKey != "pk-abc" || h.CertPEM != "pem-abc" {
		t.Errorf("host = %+v", h)
	}

	// The host row is queryable and the token is consumed.
	got, err := inv.GetHost("web01")
	if err != nil {
		t.Fatal(err)
	}
	if got.WGIP != "10.42.0.2" {
		t.Errorf("stored WGIP = %q", got.WGIP)
	}
	if _, err := inv.ValidateToken("tok1"); !errors.Is(err, ErrTokenUsed) {
		t.Errorf("token still usable after enroll: %v", err)
	}
}

func TestEnrollHostSingleUseToken(t *testing.T) {
	inv := enrollTestInv(t)
	mustToken(t, inv, "tok1", "web01", time.Hour)

	if _, err := inv.EnrollHost("tok1", "web01", "pk1", "pem1"); err != nil {
		t.Fatal(err)
	}
	// Second enroll with the same token must fail, even for a different
	// host name (the token is spent).
	_, err := inv.EnrollHost("tok1", "web02", "pk2", "pem2")
	if !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("second EnrollHost error = %v, want ErrTokenUsed", err)
	}
	// web02 must NOT exist: the failed enroll wrote nothing.
	if _, err := inv.GetHost("web02"); !errors.Is(err, ErrNotFound) {
		t.Errorf("web02 exists after failed enroll: %v", err)
	}
}

func TestEnrollHostHostnameMismatch(t *testing.T) {
	inv := enrollTestInv(t)
	mustToken(t, inv, "tok1", "web01", time.Hour)

	_, err := inv.EnrollHost("tok1", "web99", "pk", "pem")
	if err == nil {
		t.Fatal("EnrollHost accepted a hostname mismatch")
	}
	// The token must not be burned by a mismatched attempt.
	if _, err := inv.ValidateToken("tok1"); err != nil {
		t.Errorf("token unusable after mismatched attempt: %v", err)
	}
}

func TestEnrollHostExpiredToken(t *testing.T) {
	inv := enrollTestInv(t)
	mustToken(t, inv, "tok1", "web01", -time.Minute)

	_, err := inv.EnrollHost("tok1", "web01", "pk", "pem")
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("EnrollHost error = %v, want ErrTokenExpired", err)
	}
}

func TestEnrollHostUnknownToken(t *testing.T) {
	inv := enrollTestInv(t)
	_, err := inv.EnrollHost("ghost", "web01", "pk", "pem")
	if !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("EnrollHost error = %v, want ErrTokenNotFound", err)
	}
}

func TestEnrollHostRejectsDuplicateHostname(t *testing.T) {
	inv := enrollTestInv(t)
	mustToken(t, inv, "tok1", "web01", time.Hour)
	mustToken(t, inv, "tok2", "web01", time.Hour)

	if _, err := inv.EnrollHost("tok1", "web01", "pk1", "pem1"); err != nil {
		t.Fatal(err)
	}
	_, err := inv.EnrollHost("tok2", "web01", "pk2", "pem2")
	if !errors.Is(err, ErrHostExists) {
		t.Fatalf("second enroll error = %v, want ErrHostExists", err)
	}
}

func TestEnrollAllocatesNextIP(t *testing.T) {
	inv := enrollTestInv(t)
	mustToken(t, inv, "tok1", "web01", time.Hour)
	mustToken(t, inv, "tok2", "web02", time.Hour)

	h1, err := inv.EnrollHost("tok1", "web01", "pk1", "pem1")
	if err != nil {
		t.Fatal(err)
	}
	h2, err := inv.EnrollHost("tok2", "web02", "pk2", "pem2")
	if err != nil {
		t.Fatal(err)
	}
	if h1.WGIP == h2.WGIP {
		t.Errorf("both hosts got %q", h1.WGIP)
	}
	if h1.WGIP != "10.42.0.2" {
		t.Errorf("first WGIP = %q, want 10.42.0.2 (.1 is the server's)", h1.WGIP)
	}
	if h2.WGIP != "10.42.0.3" {
		t.Errorf("second WGIP = %q, want 10.42.0.3", h2.WGIP)
	}
}

func TestServerAddressIsReserved(t *testing.T) {
	inv := enrollTestInv(t)
	if inv.ServerIP() != "10.42.0.1" {
		t.Errorf("ServerIP = %q, want 10.42.0.1", inv.ServerIP())
	}
	// An explicit request for the server address is refused clearly.
	err := inv.AddHost(&Host{Hostname: "sneaky", WGIP: inv.ServerIP()})
	if !errors.Is(err, ErrIPReserved) {
		t.Fatalf("AddHost with the server IP error = %v, want ErrIPReserved", err)
	}
}

func TestLoopbackNetworkHasNoReservation(t *testing.T) {
	// Loopback dev networks share 127.0.0.1 for server and hosts (other
	// 127.x addresses are not dialable on macOS): no reservation there.
	path := filepath.Join(t.TempDir(), "inv.db")
	inv, err := Open(path, "127.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	defer inv.Close()
	h := &Host{Hostname: "web01"}
	if err := inv.AddHost(h); err != nil {
		t.Fatal(err)
	}
	if h.WGIP != "127.0.0.1" {
		t.Errorf("WGIP = %q, want 127.0.0.1 (no reservation on loopback)", h.WGIP)
	}
	if inv.IsServerIP(h.WGIP) {
		t.Error("IsServerIP true on a loopback network")
	}
}

func TestRevocationLifecycle(t *testing.T) {
	inv := enrollTestInv(t)
	if revoked, err := inv.IsRevoked("serial-1"); err != nil || revoked {
		t.Fatalf("IsRevoked fresh = %v, %v", revoked, err)
	}
	if err := inv.AddRevocation("serial-1", "web01"); err != nil {
		t.Fatalf("AddRevocation returned error: %v", err)
	}
	if revoked, err := inv.IsRevoked("serial-1"); err != nil || !revoked {
		t.Fatalf("IsRevoked after revoke = %v, %v", revoked, err)
	}
	// Idempotent re-revoke.
	if err := inv.AddRevocation("serial-1", "web01"); err != nil {
		t.Fatalf("second AddRevocation error: %v", err)
	}
	list, err := inv.ListRevocations()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Serial != "serial-1" || list[0].Hostname != "web01" {
		t.Errorf("ListRevocations = %+v", list)
	}
}
