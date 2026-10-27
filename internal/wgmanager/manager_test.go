package wgmanager

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/claymod/claymod/internal/wgmgr"
)

func TestFakeBackendLifecycle(t *testing.T) {
	backend := NewFakeBackend()
	m, err := New("claymod0", backend, "127.0.0.1:51821")
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
	keys := wgmgr.KeyPair{Private: "cHJpdg==", Public: "cHVi"}
	m := NewWithKeys("claymod0", keys, backend, "127.0.0.1:51821")
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

func TestManagerPersistsConfOnEnrollRevoke(t *testing.T) {
	path := filepath.Join(t.TempDir(), "claymod0.conf")
	backend := NewFakeBackend()
	m := NewWithKeys("claymod0", wgmgr.KeyPair{Private: "PRIV", Public: "PUB"},
		backend, "127.0.0.1:51821")
	m.Overlay = "10.42.0.1/24"
	m.ListenPort = 51821
	m.ConfPath = path

	if err := m.Enroll("web01", "PK1", "10.42.0.2"); err != nil {
		t.Fatalf("Enroll returned error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("conf not written on enroll: %v", err)
	}
	if !strings.Contains(string(data), "# web01") || !strings.Contains(string(data), "10.42.0.2/32") {
		t.Errorf("conf missing web01 peer:\n%s", data)
	}

	if err := m.Revoke("PK1"); err != nil {
		t.Fatalf("Revoke returned error: %v", err)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "# web01") {
		t.Errorf("conf still lists revoked web01:\n%s", data)
	}
}

func TestResyncInstallsInventoryPeers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "claymod0.conf")
	m := NewWithKeys("claymod0", wgmgr.KeyPair{Private: "PRIV"}, NewFakeBackend(), "")
	m.Overlay = "10.42.0.1/24"
	m.ListenPort = 51821
	m.ConfPath = path

	// Simulate a restart: inventory hands back two hosts.
	if err := m.Resync([]wgmgr.Peer{
		{Hostname: "web01", PublicKey: "PK1", AllowedIPs: "10.42.0.2/32"},
		{Hostname: "web02", PublicKey: "PK2", AllowedIPs: "10.42.0.3/32"},
	}); err != nil {
		t.Fatalf("Resync returned error: %v", err)
	}
	peers, err := m.Peers()
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 2 {
		t.Fatalf("Peers after resync = %d, want 2", len(peers))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# web01", "# web02", "10.42.0.2/32", "10.42.0.3/32"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("conf missing %q after resync", want)
		}
	}
}

// TestEnsureInterfaceUsesSystemCommands verifies the command sequence
// (create link, set address, wg set with a key file, link up) against a
// recorded runner — no root required.

func TestPeersFuncIsSourceOfTruth(t *testing.T) {
	path := filepath.Join(t.TempDir(), "claymod0.conf")
	m := NewWithKeys("claymod0", wgmgr.KeyPair{Private: "PRIV"}, NewFakeBackend(), "")
	m.Overlay = "10.42.0.1/24"
	m.ListenPort = 51821
	m.ConfPath = path

	dbPeers := []wgmgr.Peer{
		{Hostname: "web01", PublicKey: "PK1", AllowedIPs: "10.42.0.2/32"},
	}
	m.PeersFunc = func() ([]wgmgr.Peer, error) { return dbPeers, nil }

	// Enroll adds to the map AND (via PeersFunc) to the conf.
	if err := m.Enroll("web01", "PK1", "10.42.0.2"); err != nil {
		t.Fatal(err)
	}
	// Simulate `host revoke` removing web01 from the DB behind serve's
	// back: the next refresh must drop it from the file.
	dbPeers = nil
	if err := m.RefreshConf(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "# web01") {
		t.Errorf("conf resurrected a DB-removed peer:\n%s", data)
	}
}

type cmdErr string
