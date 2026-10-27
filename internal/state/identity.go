package state

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	"github.com/claymod/claymod/internal/proto"
)

// ControlIdentity is the control server's mTLS identity plus the CA pool
// used to verify agents — exactly what the runner, `exec` and `host
// facts` need to dial an agent. It is read-only: nothing is created.
type ControlIdentity struct {
	Identity   proto.Identity
	ServerPool *x509.CertPool
}

// Load reads the full control-server state from an existing data
// directory without creating anything. Unlike Open, a missing or
// uninitialized directory is an error: client commands must never mint
// a fresh CA that no agent trusts.
func Load(dir string) (*State, error) {
	if _, err := os.Stat(filepath.Join(dir, "ca", "ca.pem")); err != nil {
		return nil, fmt.Errorf("state: %s is not initialized (has `claymod serve` run against it?): %w", dir, err)
	}
	// Open only *creates* what is missing; the CA exists, so the rest is
	// read or issued-if-absent. Every identity file must already exist —
	// in particular wg-keys.json: a silently regenerated WireGuard key
	// would desync the live interface.
	for _, name := range []string{serverCert, controlCert, wgKeysFile} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			return nil, fmt.Errorf("state: %s missing in %s (incomplete initialization): %w", name, dir, err)
		}
	}
	return Open(dir, "claymod")
}

// LoadControlIdentity reads the control-side identity from an existing
// data directory (as created by serve). Unlike Open, it never creates
// anything: `claymod exec` / `host facts` against a missing or
// uninitialized data dir fail with a clear error instead of silently
// minting a new CA that no agent trusts.
func LoadControlIdentity(dir string) (*ControlIdentity, error) {
	readPEM := func(name string) ([]byte, error) {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("state: read %s (has `claymod serve` initialized %s?): %w",
				name, dir, err)
		}
		return data, nil
	}

	caPEM, err := readPEM(filepath.Join("ca", "ca.pem"))
	if err != nil {
		return nil, err
	}
	pool, err := proto.CertPoolFromPEM(caPEM)
	if err != nil {
		return nil, fmt.Errorf("state: parse CA bundle: %w", err)
	}
	certPEM, err := readPEM(controlCert)
	if err != nil {
		return nil, err
	}
	keyPEM, err := readPEM(controlKey)
	if err != nil {
		return nil, err
	}
	id, err := proto.LoadIdentity(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("state: load control identity: %w", err)
	}
	return &ControlIdentity{Identity: id, ServerPool: pool}, nil
}
