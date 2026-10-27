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
