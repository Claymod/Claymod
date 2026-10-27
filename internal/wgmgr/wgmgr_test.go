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
