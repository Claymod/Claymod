package state

import (
	"crypto/x509"
	"net"
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

func TestOpenBareIPServerNameIssuesIPSAN(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, "51.38.34.49")
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	cert, err := x509.ParseCertificate(s.ServerID.Certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(net.ParseIP("51.38.34.49")) {
		t.Errorf("IP SANs = %v, want [51.38.34.49]", cert.IPAddresses)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "localhost" {
		t.Errorf("DNS SANs = %v, want [localhost]", cert.DNSNames)
	}

	// Reopening with the same IP keeps the certificate (idempotent).
	s2, err := Open(dir, "51.38.34.49")
	if err != nil {
		t.Fatal(err)
	}
	if string(s2.ServerID.Certificate.Certificate[0]) != string(s.ServerID.Certificate.Certificate[0]) {
		t.Error("server certificate re-issued although serverName did not change")
	}
}

func TestOpenReissuesOnServerNameChange(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, "claymod.internal")
	if err != nil {
		t.Fatal(err)
	}
	oldCert := s.ServerID.Certificate.Certificate[0]

	// A different serverName must trigger a re-issue (stale SANs would
	// break agents' hostname verification). The CA stays the same.
	s2, err := Open(dir, "51.38.34.49")
	if err != nil {
		t.Fatalf("Open with new serverName: %v", err)
	}
	newCert := s2.ServerID.Certificate.Certificate[0]
	if string(newCert) == string(oldCert) {
		t.Fatal("server certificate not re-issued after serverName change")
	}
	parsed, err := x509.ParseCertificate(newCert)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ip := range parsed.IPAddresses {
		if ip.Equal(net.ParseIP("51.38.34.49")) {
			found = true
		}
	}
	if !found {
		t.Errorf("re-issued cert IP SANs = %v, want 51.38.34.49", parsed.IPAddresses)
	}
	if string(s2.CA.CertPEM()) != string(s.CA.CertPEM()) {
		t.Error("CA changed across serverName change")
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
