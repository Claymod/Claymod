// Package state manages the control server's data directory: the
// internal CA, the server's mTLS identity and its WireGuard key pair are
// created on first run and reloaded afterwards.
package state

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/claymod/claymod/internal/ca"
	"github.com/claymod/claymod/internal/proto"
	"github.com/claymod/claymod/internal/wgmgr"
)

const (
	caDir         = "ca"
	serverCert    = "server.pem"
	serverKey     = "server-key.pem"
	controlCert   = "control.pem"
	controlKey    = "control-key.pem"
	wgKeysFile    = "wg-keys.json"
	inventoryFile = "inventory.db"
)

// State is the loaded control-server state.
type State struct {
	// Dir is the data directory.
	Dir string
	// CA is the internal root authority.
	CA *ca.CA
	// ServerID is the server's mTLS identity (client certs verify it).
	ServerID proto.Identity
	// ControlID is the control server's own client identity: the runner
	// (and probes) present it when dialing agents over mTLS.
	ControlID proto.Identity
	// WGKeys is the server's WireGuard identity.
	WGKeys wgmgr.KeyPair
	// InventoryPath is the sqlite database path.
	InventoryPath string
}

// Open loads the state from dir, creating and initializing anything
// missing. serverName is the CN/SAN on the server certificate (agents
// verify it by this name).
func Open(dir, serverName string) (*State, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("state: create data dir: %w", err)
	}
	s := &State{Dir: dir, InventoryPath: filepath.Join(dir, inventoryFile)}

	// CA: load or create.
	authority, err := ca.Load(filepath.Join(dir, caDir))
	if err != nil {
		authority, err = ca.New("claymod-ca")
		if err != nil {
			return nil, err
		}
		if err := authority.Save(filepath.Join(dir, caDir)); err != nil {
			return nil, err
		}
	}
	s.CA = authority

	// Server identity: load or issue. Re-issued when the stored
	// certificate no longer matches serverName (e.g. the operator
	// changed --server-name, or moved between a DNS name and a bare IP):
	// agents verify the bootstrap endpoint by this name, so a stale
	// certificate would break enrollment. The CA is untouched — its
	// fingerprint (the agents' pin) stays stable.
	certPath := filepath.Join(dir, serverCert)
	keyPath := filepath.Join(dir, serverKey)
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr != nil || keyErr != nil || !serverCertMatches(certPEM, serverName) {
		certPEM, keyPEM, err = issueServerCert(authority, serverName)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
			return nil, err
		}
		if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
			return nil, err
		}
	}
	s.ServerID, err = proto.LoadIdentity(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	// Control client identity: used by the runner to dial agents (mTLS
	// client certificate).
	ctrlCertPath := filepath.Join(dir, controlCert)
	ctrlKeyPath := filepath.Join(dir, controlKey)
	ctrlCertPEM, ctrlCertErr := os.ReadFile(ctrlCertPath)
	ctrlKeyPEM, ctrlKeyErr := os.ReadFile(ctrlKeyPath)
	if ctrlCertErr != nil || ctrlKeyErr != nil {
		ctrlCertPEM, ctrlKeyPEM, err = authority.IssueCert(ca.IssueOptions{
			CommonName: "claymod-control",
			Usage:      ca.UsageClient,
		})
		if err != nil {
			return nil, fmt.Errorf("state: issue control certificate: %w", err)
		}
		if err := os.WriteFile(ctrlCertPath, ctrlCertPEM, 0o644); err != nil {
			return nil, err
		}
		if err := os.WriteFile(ctrlKeyPath, ctrlKeyPEM, 0o600); err != nil {
			return nil, err
		}
	}
	s.ControlID, err = proto.LoadIdentity(ctrlCertPEM, ctrlKeyPEM)
	if err != nil {
		return nil, err
	}

	// WireGuard keys: load or generate.
	keysPath := filepath.Join(dir, wgKeysFile)
	raw, err := os.ReadFile(keysPath)
	if err != nil {
		s.WGKeys, err = wgmgr.GenerateKeyPair()
		if err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(s.WGKeys)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(keysPath, encoded, 0o600); err != nil {
			return nil, err
		}
	} else {
		if err := json.Unmarshal(raw, &s.WGKeys); err != nil {
			return nil, fmt.Errorf("state: parse wg keys: %w", err)
		}
	}
	return s, nil
}

// issueServerCert issues the bootstrap server's leaf certificate. An
// IP-form serverName becomes an IP SAN (curl and Go verify IP targets
// against IPAddresses, and ignore a DNS SAN that merely looks like an
// IP); a DNS name lands in DNSNames alongside localhost.
func issueServerCert(authority *ca.CA, serverName string) (certPEM, keyPEM []byte, err error) {
	opts := ca.IssueOptions{
		CommonName: serverName,
		Usage:      ca.UsageServer,
		DNSNames:   []string{"localhost"},
	}
	if netIP := net.ParseIP(serverName); netIP != nil {
		opts.IPAddresses = []net.IP{netIP}
	} else {
		opts.DNSNames = append([]string{serverName}, opts.DNSNames...)
	}
	certPEM, keyPEM, err = authority.IssueCert(opts)
	if err != nil {
		return nil, nil, fmt.Errorf("state: issue server certificate: %w", err)
	}
	return certPEM, keyPEM, nil
}

// serverCertMatches reports whether the stored server certificate still
// covers serverName (and is currently valid). A non-parsing certificate
// counts as mismatched so it gets re-issued.
func serverCertMatches(certPEM []byte, serverName string) bool {
	cert, err := ca.ParseCertPEM(certPEM)
	if err != nil {
		return false
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return false
	}
	if netIP := net.ParseIP(serverName); netIP != nil {
		for _, certIP := range cert.IPAddresses {
			if certIP.Equal(netIP) {
				return true
			}
		}
		return false
	}
	for _, name := range cert.DNSNames {
		if strings.EqualFold(name, serverName) {
			return true
		}
	}
	return false
}
