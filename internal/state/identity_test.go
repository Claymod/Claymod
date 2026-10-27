package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadControlIdentityHappyPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if _, err := Open(dir, "claymod.internal"); err != nil {
		t.Fatal(err)
	}
	ctrl, err := LoadControlIdentity(dir)
	if err != nil {
		t.Fatalf("LoadControlIdentity returned error: %v", err)
	}
	if ctrl.Identity.Certificate.PrivateKey == nil {
		t.Error("control identity has no key")
	}
	if ctrl.ServerPool == nil {
		t.Error("server pool missing")
	}
}

func TestLoadControlIdentityIsReadOnly(t *testing.T) {
	// A missing data dir must fail loudly — never silently mint a new CA
	// no agent trusts.
	dir := filepath.Join(t.TempDir(), "does-not-exist")
	if _, err := LoadControlIdentity(dir); err == nil {
		t.Fatal("LoadControlIdentity created state in a missing directory")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("LoadControlIdentity created the data dir")
	}
}

func TestLoadIsReadOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing")
	if _, err := Load(dir); err == nil {
		t.Fatal("Load accepted a missing data dir")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("Load created the data dir")
	}

	// After a real Open, Load reads the same state (same WG keys).
	real := filepath.Join(t.TempDir(), "data")
	s1, err := Open(real, "claymod.internal")
	if err != nil {
		t.Fatal(err)
	}
	s2, err := Load(real)
	if err != nil {
		t.Fatalf("Load after Open returned error: %v", err)
	}
	if s2.WGKeys.Public != s1.WGKeys.Public {
		t.Error("Load rotated the WireGuard keys")
	}
}

func TestLoadControlIdentityMissingFiles(t *testing.T) {
	dir := t.TempDir()
	// Empty dir: the error must point at serve as the initializer.
	_, err := LoadControlIdentity(dir)
	if err == nil {
		t.Fatal("LoadControlIdentity accepted an empty dir")
	}
	if !strings.Contains(err.Error(), "claymod serve") {
		t.Errorf("error = %q, want a pointer to `claymod serve`", err.Error())
	}
}
