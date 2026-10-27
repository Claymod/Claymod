package wgmgr

import (
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair returned error: %v", err)
	}
	if len(kp.Private) == 0 || len(kp.Public) == 0 {
		t.Fatalf("key pair empty: %+v", kp)
	}
	if kp.Private == kp.Public {
		t.Error("private and public keys identical")
	}

	// PublicFromPrivate must reproduce the generated public key.
	pub, err := PublicFromPrivate(kp.Private)
	if err != nil {
		t.Fatalf("PublicFromPrivate returned error: %v", err)
	}
	if pub != kp.Public {
		t.Errorf("derived public %q, want %q", pub, kp.Public)
	}
}

func TestKeyPairsAreUnique(t *testing.T) {
	a, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if a.Public == b.Public {
		t.Error("two key pairs share a public key")
	}
}

func TestPublicFromPrivateRejectsGarbage(t *testing.T) {
	if _, err := PublicFromPrivate("not-base64!"); err == nil {
		t.Error("PublicFromPrivate accepted garbage")
	}
	if _, err := PublicFromPrivate("aGVsbG8="); err == nil {
		t.Error("PublicFromPrivate accepted a short key")
	}
}

func TestFakeBackendLifecycle(t *testing.T) {
	backend := NewFakeBackend()
	m, err := New("claymod0", backend, "127.0.0.1:51820")
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if m.ControlKeys.Public == "" {
		t.Fatal("manager has no control public key")
	}

	if err := m.Enroll("web01", "pk-web01", "10.42.0.1"); err != nil {
		t.Fatalf("Enroll returned error: %v", err)
	}
	if err := m.Enroll("web02", "pk-web02", "10.42.0.2"); err != nil {
		t.Fatalf("Enroll returned error: %v", err)
	}
	peers, err := m.Peers()
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 2 {
		t.Fatalf("Peers = %d, want 2", len(peers))
	}
	// AllowedIPs carry the /32.
	for _, p := range peers {
		if len(p.AllowedIPs) < 3 || p.AllowedIPs[len(p.AllowedIPs)-3:] != "/32" {
			t.Errorf("peer %s AllowedIPs = %q, want /32 suffix", p.PublicKey, p.AllowedIPs)
		}
	}

	// Revoke removes one peer.
	if err := m.Revoke("pk-web01"); err != nil {
		t.Fatalf("Revoke returned error: %v", err)
	}
	peers, err = m.Peers()
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 || peers[0].PublicKey != "pk-web02" {
		t.Errorf("Peers after revoke = %+v", peers)
	}
	// Revoking an unknown peer is an error.
	if err := m.Revoke("ghost"); err == nil {
		t.Error("Revoke accepted an unknown peer")
	}
	// Empty key is a no-op (idempotent revoke).
	if err := m.Revoke(""); err != nil {
		t.Errorf("Revoke(\"\") = %v, want nil", err)
	}
}

func TestNewWithKeysRestores(t *testing.T) {
	backend := NewFakeBackend()
	keys := KeyPair{Private: "cHJpdg==", Public: "cHVi"}
	m := NewWithKeys("claymod0", keys, backend, "127.0.0.1:51820")
	if m.ControlKeys.Public != "cHVi" {
		t.Errorf("ControlKeys = %+v", m.ControlKeys)
	}
}

func TestParseAllowedIP(t *testing.T) {
	_, ipNet, err := parseAllowedIP("10.42.0.7/32")
	if err != nil {
		t.Fatalf("parseAllowedIP returned error: %v", err)
	}
	if ipNet.String() != "10.42.0.7/32" {
		t.Errorf("ipNet = %q", ipNet.String())
	}
	_, ipNet, err = parseAllowedIP("10.42.0.8")
	if err != nil {
		t.Fatalf("bare IP parse returned error: %v", err)
	}
	if ipNet.String() != "10.42.0.8/32" {
		t.Errorf("bare ipNet = %q, want /32 default", ipNet.String())
	}
	if _, _, err := parseAllowedIP(""); err == nil {
		t.Error("parseAllowedIP accepted empty input")
	}
	if _, _, err := parseAllowedIP("not-an-ip"); err == nil {
		t.Error("parseAllowedIP accepted garbage")
	}
}
