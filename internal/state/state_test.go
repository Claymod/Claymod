package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenCreatesState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	s, err := Open(dir, "claymod.internal")
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	if s.CA == nil || s.ServerID.Certificate.PrivateKey == nil {
		t.Fatal("state incomplete after init")
	}
	if s.ControlID.Certificate.PrivateKey == nil {
		t.Fatal("control client identity missing")
	}
	if s.WGKeys.Public == "" || s.WGKeys.Private == "" {
		t.Fatalf("WG keys empty: %+v", s.WGKeys)
	}

	// Idempotent open: same CA, same server cert, same WG keys.
	s2, err := Open(dir, "claymod.internal")
	if err != nil {
		t.Fatalf("second Open returned error: %v", err)
	}
	if s2.WGKeys.Public != s.WGKeys.Public {
		t.Error("WG public key changed across restarts")
	}
	if string(s2.CA.CertPEM()) != string(s.CA.CertPEM()) {
		t.Error("CA changed across restarts")
	}
}

func TestOpenPersistsFiles(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir, "claymod.internal"); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(dir, "ca", "ca.pem"),
		filepath.Join(dir, "ca", "ca-key.pem"),
		filepath.Join(dir, "server.pem"),
		filepath.Join(dir, "server-key.pem"),
		filepath.Join(dir, "wg-keys.json"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("missing state file %s: %v", path, err)
		}
	}
}
