package inventory

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

const testNetwork = "10.42.0.0/24"

func openTestInv(t *testing.T) *Inventory {
	t.Helper()
	path := filepath.Join(t.TempDir(), "inventory.db")
	inv, err := Open(path, testNetwork)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	t.Cleanup(func() { inv.Close() })
	return inv
}

func TestAddHostAllocatesFirstIP(t *testing.T) {
	inv := openTestInv(t)
	h := &Host{Hostname: "web01"}
	if err := inv.AddHost(h); err != nil {
		t.Fatalf("AddHost returned error: %v", err)
	}
	if h.WGIP != "10.42.0.1" {
		t.Errorf("WGIP = %q, want 10.42.0.1", h.WGIP)
	}
}

func TestAddHostRejectsDuplicateHostname(t *testing.T) {
	inv := openTestInv(t)
	if err := inv.AddHost(&Host{Hostname: "web01"}); err != nil {
		t.Fatal(err)
	}
	err := inv.AddHost(&Host{Hostname: "web01"})
	if !errors.Is(err, ErrHostExists) {
		t.Fatalf("second AddHost error = %v, want ErrHostExists", err)
	}
}

func TestAddHostRejectsDuplicateIP(t *testing.T) {
	inv := openTestInv(t)
	if err := inv.AddHost(&Host{Hostname: "web01", WGIP: "10.42.0.5"}); err != nil {
		t.Fatal(err)
	}
	err := inv.AddHost(&Host{Hostname: "web02", WGIP: "10.42.0.5"})
	if !errors.Is(err, ErrIPInUse) {
		t.Fatalf("AddHost with duplicate IP error = %v, want ErrIPInUse", err)
	}
}

func TestAddHostRejectsOutOfRangeIP(t *testing.T) {
	inv := openTestInv(t)
	err := inv.AddHost(&Host{Hostname: "web01", WGIP: "10.43.0.5"})
	if !errors.Is(err, ErrIPOutOfRange) {
		t.Fatalf("AddHost error = %v, want ErrIPOutOfRange", err)
	}
}

func TestIPReuseAfterRevoke(t *testing.T) {
	inv := openTestInv(t)
	if err := inv.AddHost(&Host{Hostname: "web01"}); err != nil {
		t.Fatal(err)
	}
	if err := inv.AddHost(&Host{Hostname: "web02"}); err != nil {
		t.Fatal(err)
	}
	// Revoke web01 (frees .1), then web03 must reuse it.
	if err := inv.RemoveHost("web01"); err != nil {
		t.Fatalf("RemoveHost returned error: %v", err)
	}
	h3 := &Host{Hostname: "web03"}
	if err := inv.AddHost(h3); err != nil {
		t.Fatalf("AddHost after revoke returned error: %v", err)
	}
	if h3.WGIP != "10.42.0.1" {
		t.Errorf("web03 WGIP = %q, want freed 10.42.0.1", h3.WGIP)
	}
}

func TestRemoveHostUnknownFails(t *testing.T) {
	inv := openTestInv(t)
	err := inv.RemoveHost("ghost")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("RemoveHost error = %v, want ErrNotFound", err)
	}
}

func TestAllocationSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inventory.db")

	inv, err := Open(path, testNetwork)
	if err != nil {
		t.Fatal(err)
	}
	if err := inv.AddHost(&Host{Hostname: "web01"}); err != nil {
		t.Fatal(err)
	}
	if err := inv.AddHost(&Host{Hostname: "web02"}); err != nil {
		t.Fatal(err)
	}
	if err := inv.Close(); err != nil {
		t.Fatal(err)
	}

	// Simulate restart: reopen and allocate again — must continue at .3,
	// not hand out an already-used address.
	inv2, err := Open(path, testNetwork)
	if err != nil {
		t.Fatalf("reopen returned error: %v", err)
	}
	defer inv2.Close()
	h3 := &Host{Hostname: "web03"}
	if err := inv2.AddHost(h3); err != nil {
		t.Fatal(err)
	}
	if h3.WGIP != "10.42.0.3" {
		t.Errorf("after restart WGIP = %q, want 10.42.0.3", h3.WGIP)
	}
	ips, err := inv2.AllocatedIPs()
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 3 {
		t.Errorf("AllocatedIPs = %v, want 3 entries", ips)
	}
}

func TestGetAndListHosts(t *testing.T) {
	inv := openTestInv(t)
	for _, name := range []string{"web02", "web01", "db01"} {
		if err := inv.AddHost(&Host{Hostname: name}); err != nil {
			t.Fatal(err)
		}
	}
	h, err := inv.GetHost("web01")
	if err != nil {
		t.Fatalf("GetHost returned error: %v", err)
	}
	if h.WGIP != "10.42.0.2" {
		t.Errorf("web01 WGIP = %q, want 10.42.0.2", h.WGIP)
	}
	if _, err := inv.GetHost("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetHost(nope) error = %v, want ErrNotFound", err)
	}
	hosts, err := inv.ListHosts()
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 3 {
		t.Fatalf("ListHosts len = %d, want 3", len(hosts))
	}
	wantOrder := []string{"db01", "web01", "web02"}
	for k, name := range wantOrder {
		if hosts[k].Hostname != name {
			t.Errorf("ListHosts[%d] = %q, want %q", k, hosts[k].Hostname, name)
		}
	}
}

func TestUpdateHost(t *testing.T) {
	inv := openTestInv(t)
	if err := inv.AddHost(&Host{Hostname: "web01"}); err != nil {
		t.Fatal(err)
	}
	h := &Host{
		Hostname:  "web01",
		PublicKey: "pk-abc",
		CertPEM:   "pem-abc",
		Facts:     `{"os":"linux"}`,
		LastSeen:  time.Now(),
	}
	if err := inv.UpdateHost(h); err != nil {
		t.Fatalf("UpdateHost returned error: %v", err)
	}
	got, err := inv.GetHost("web01")
	if err != nil {
		t.Fatal(err)
	}
	if got.PublicKey != "pk-abc" || got.CertPEM != "pem-abc" || got.Facts != `{"os":"linux"}` {
		t.Errorf("UpdateHost did not persist: %+v", got)
	}
	err = inv.UpdateHost(&Host{Hostname: "ghost"})
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateHost(ghost) error = %v, want ErrNotFound", err)
	}
}

func TestTokenLifecycle(t *testing.T) {
	inv := openTestInv(t)
	if err := inv.StoreToken("tok1", "web01", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("StoreToken returned error: %v", err)
	}
	hostname, err := inv.ValidateToken("tok1")
	if err != nil {
		t.Fatalf("ValidateToken returned error: %v", err)
	}
	if hostname != "web01" {
		t.Errorf("ValidateToken hostname = %q, want web01", hostname)
	}
	// Consume once.
	if _, err := inv.ConsumeToken("tok1"); err != nil {
		t.Fatalf("ConsumeToken returned error: %v", err)
	}
	// Second consume must fail.
	if _, err := inv.ConsumeToken("tok1"); !errors.Is(err, ErrTokenUsed) {
		t.Errorf("second ConsumeToken error = %v, want ErrTokenUsed", err)
	}
}

func TestTokenExpired(t *testing.T) {
	inv := openTestInv(t)
	if err := inv.StoreToken("tok-exp", "web01", time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := inv.ValidateToken("tok-exp"); !errors.Is(err, ErrTokenExpired) {
		t.Errorf("ValidateToken error = %v, want ErrTokenExpired", err)
	}
}

func TestTokenUnknown(t *testing.T) {
	inv := openTestInv(t)
	if _, err := inv.ValidateToken("ghost"); !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("ValidateToken error = %v, want ErrTokenNotFound", err)
	}
}

func TestIPAMExhaustion(t *testing.T) {
	// /30 gives network + broadcast + 2 usable → exhaustion is reachable.
	inv, err := Open(filepath.Join(t.TempDir(), "inv.db"), "10.99.0.0/30")
	if err != nil {
		t.Fatal(err)
	}
	defer inv.Close()
	for k, name := range []string{"a", "b"} {
		if err := inv.AddHost(&Host{Hostname: name}); err != nil {
			t.Fatalf("AddHost %s: %v", name, err)
		}
		_ = k
	}
	err = inv.AddHost(&Host{Hostname: "c"})
	if !errors.Is(err, ErrIPExhausted) {
		t.Fatalf("AddHost past exhaustion error = %v, want ErrIPExhausted", err)
	}
}

func TestIPAMRejectsBadNetwork(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "inv.db"), "not-a-cidr"); err == nil {
		t.Fatal("Open accepted a bad agent network")
	}
	if _, err := Open(filepath.Join(t.TempDir(), "inv.db"), "fd00::/64"); err == nil {
		t.Fatal("Open accepted an IPv6 agent network")
	}
}
