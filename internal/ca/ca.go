// Package ca implements the internal certificate authority used by the
// control server and enrolled agents for mutual TLS over the WireGuard
// overlay. The root key never leaves the control server's data dir.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	rootCertFile = "ca.pem"
	rootKeyFile  = "ca-key.pem"

	rootValidity = 10 * 365 * 24 * time.Hour
	leafValidity = 365 * 24 * time.Hour
)

// CertUsage says how a leaf certificate may be used.
type CertUsage int

const (
	// UsageClient is for agents (verified by the control server).
	UsageClient CertUsage = iota
	// UsageServer is for the control server's TLS listeners.
	UsageServer
)

// IssueOptions describes a leaf certificate to issue.
type IssueOptions struct {
	// CommonName is the certificate subject CN; for client certs this is
	// the host's name and is matched against the inventory hostname.
	CommonName string
	// Usage selects the extended key usage embedded in the certificate.
	Usage CertUsage
	// Validity defaults to one year when zero.
	Validity time.Duration
	// DNSNames and IPAddresses are optional SANs (needed for server certs
	// whose clients verify by name or address).
	DNSNames    []string
	IPAddresses []net.IP
}

// CA is the internal root authority.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// New generates a fresh self-signed root CA.
func New(commonName string) (*CA, error) {
	if commonName == "" {
		commonName = "claymod-ca"
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate root key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(rootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("create root certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse root certificate: %w", err)
	}
	return &CA{cert: cert, key: key}, nil
}

// IssueCert issues a leaf certificate signed by this CA. The returned
// values are PEM-encoded certificate and EC private key.
func (c *CA) IssueCert(opts IssueOptions) (certPEM, keyPEM []byte, err error) {
	if opts.CommonName == "" {
		return nil, nil, fmt.Errorf("common name is required")
	}
	validity := opts.Validity
	if validity <= 0 {
		validity = leafValidity
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: opts.CommonName},
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     opts.DNSNames,
		IPAddresses:  opts.IPAddresses,
	}
	switch opts.Usage {
	case UsageClient:
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case UsageServer:
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	default:
		return nil, nil, fmt.Errorf("unknown cert usage %d", opts.Usage)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, key.Public(), c.key)
	if err != nil {
		return nil, nil, fmt.Errorf("create leaf certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal leaf key: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// Verify checks that certPEM was issued by this CA for the given usage and
// is currently valid. It returns the parsed leaf certificate.
func (c *CA) Verify(certPEM []byte, usage CertUsage) (*x509.Certificate, error) {
	cert, err := ParseCertPEM(certPEM)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(c.cert)
	extUsage := x509.ExtKeyUsageClientAuth
	if usage == UsageServer {
		extUsage = x509.ExtKeyUsageServerAuth
	}
	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{extUsage},
	}
	if _, err := cert.Verify(opts); err != nil {
		return nil, fmt.Errorf("verify certificate %q: %w", cert.Subject.CommonName, err)
	}
	return cert, nil
}

// Certificate returns the root certificate.
func (c *CA) Certificate() *x509.Certificate { return c.cert }

// CertPEM returns the PEM-encoded root certificate.
func (c *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})
}

// Pool returns a certificate pool containing the root certificate.
func (c *CA) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(c.cert)
	return pool
}

// Save writes the root key and certificate into dir. The key file is
// written with mode 0600.
func (c *CA) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create ca dir: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(c.key)
	if err != nil {
		return fmt.Errorf("marshal root key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(dir, rootKeyFile), keyPEM, 0o600); err != nil {
		return fmt.Errorf("write root key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, rootCertFile), c.CertPEM(), 0o644); err != nil {
		return fmt.Errorf("write root cert: %w", err)
	}
	return nil
}

// Load reads a CA previously written by Save.
func Load(dir string) (*CA, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, rootCertFile))
	if err != nil {
		return nil, fmt.Errorf("read root cert: %w", err)
	}
	cert, err := ParseCertPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("parse root cert: %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, rootKeyFile))
	if err != nil {
		return nil, fmt.Errorf("read root key: %w", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("parse root key: no PEM block")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse root key: %w", err)
	}
	return &CA{cert: cert, key: key}, nil
}

// ParseCertPEM decodes a single PEM certificate.
func ParseCertPEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("parse certificate: no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}

// ParseCertPair decodes a PEM certificate and EC key pair (for loading
// server or client identities).
func ParseCertPair(certPEM, keyPEM []byte) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cert, err := ParseCertPEM(certPEM)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("parse key: no PEM block")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse key: %w", err)
	}
	return cert, key, nil
}

func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	return serial, nil
}
