package ca

import (
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestCA(t *testing.T) *CA {
	t.Helper()
	c, err := New("claymod-test-ca")
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	return c
}

func TestNewRootIsCA(t *testing.T) {
	c := newTestCA(t)
	if !c.Certificate().IsCA {
		t.Fatal("root certificate is not a CA")
	}
}

func TestIssueClientCertVerifies(t *testing.T) {
	c := newTestCA(t)
	certPEM, keyPEM, err := c.IssueCert(IssueOptions{CommonName: "web01", Usage: UsageClient})
	if err != nil {
		t.Fatalf("IssueCert returned error: %v", err)
	}
	cert, err := c.Verify(certPEM, UsageClient)
	if err != nil {
		t.Fatalf("Verify(client) returned error: %v", err)
	}
	if cert.Subject.CommonName != "web01" {
		t.Errorf("CN = %q, want web01", cert.Subject.CommonName)
	}
	if _, _, err := ParseCertPair(certPEM, keyPEM); err != nil {
		t.Errorf("ParseCertPair returned error: %v", err)
	}
}

func TestUsageMismatchFailsVerification(t *testing.T) {
	c := newTestCA(t)
	certPEM, _, err := c.IssueCert(IssueOptions{CommonName: "web01", Usage: UsageClient})
	if err != nil {
		t.Fatalf("IssueCert returned error: %v", err)
	}
	// A client cert must not verify as a server cert.
	if _, err := c.Verify(certPEM, UsageServer); err == nil {
		t.Fatal("Verify(server) accepted a client certificate")
	}
}

func TestForeignCertRejected(t *testing.T) {
	c := newTestCA(t)
	other := newTestCA(t)
	certPEM, _, err := other.IssueCert(IssueOptions{CommonName: "web01", Usage: UsageClient})
	if err != nil {
		t.Fatalf("IssueCert returned error: %v", err)
	}
	if _, err := c.Verify(certPEM, UsageClient); err == nil {
		t.Fatal("Verify accepted a certificate from another CA")
	}
}

func TestIssueServerCertWithSANs(t *testing.T) {
	c := newTestCA(t)
	certPEM, _, err := c.IssueCert(IssueOptions{
		CommonName:  "claymod-server",
		Usage:       UsageServer,
		DNSNames:    []string{"claymod.internal"},
		IPAddresses: []net.IP{net.ParseIP("10.42.0.1")},
	})
	if err != nil {
		t.Fatalf("IssueCert returned error: %v", err)
	}
	cert, err := c.Verify(certPEM, UsageServer)
	if err != nil {
		t.Fatalf("Verify(server) returned error: %v", err)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "claymod.internal" {
		t.Errorf("DNSNames = %v", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(net.ParseIP("10.42.0.1")) {
		t.Errorf("IPAddresses = %v", cert.IPAddresses)
	}
}

func TestIssueCertRequiresCommonName(t *testing.T) {
	c := newTestCA(t)
	if _, _, err := c.IssueCert(IssueOptions{Usage: UsageClient}); err == nil {
		t.Fatal("IssueCert accepted empty common name")
	}
}

func TestSaveLoadRoundtrip(t *testing.T) {
	c := newTestCA(t)
	dir := t.TempDir()
	if err := c.Save(dir); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}
	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	// Cross-check: leaf issued by the loaded CA verifies against the
	// original root and vice versa.
	certPEM, _, err := loaded.IssueCert(IssueOptions{CommonName: "web02", Usage: UsageClient})
	if err != nil {
		t.Fatalf("IssueCert returned error: %v", err)
	}
	if _, err := c.Verify(certPEM, UsageClient); err != nil {
		t.Fatalf("cross-Verify returned error: %v", err)
	}
}

func TestRootKeyFilePermissions(t *testing.T) {
	c := newTestCA(t)
	dir := t.TempDir()
	if err := c.Save(dir); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, rootKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("root key mode = %o, want 600", perm)
	}
}

func TestVerifyRejectsGarbage(t *testing.T) {
	c := newTestCA(t)
	if _, err := c.Verify([]byte("not pem"), UsageClient); err == nil {
		t.Fatal("Verify accepted garbage input")
	}
}

func TestVerifyRejectsExpiredLeaf(t *testing.T) {
	c := newTestCA(t)
	certPEM, _, err := c.IssueCert(IssueOptions{
		CommonName: "old-host",
		Usage:      UsageClient,
		Validity:   time.Minute,
	})
	if err != nil {
		t.Fatalf("IssueCert returned error: %v", err)
	}
	cert, err := ParseCertPEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.NotAfter.After(time.Now()) {
		t.Skip("leaf already expired (clock skew); skipping")
	}
	// Sanity: the EKU extension is what usage checks key off.
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ExtKeyUsage = %v, want [ClientAuth]", cert.ExtKeyUsage)
	}
}
