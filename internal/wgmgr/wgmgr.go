// Package wgmgr manages WireGuard peers for the claymod overlay: key
// generation, peer add/remove and IP allocation from the inventory's
// persistent IPAM. Kernel interaction is behind a Backend so tests run
// without root (FakeBackend) while the control server drives a real
// interface through wgctrl (NetlinkBackend).
package wgmgr

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
)

// KeyPair is a Curve25519 WireGuard key pair (base64, wg set format).
type KeyPair struct {
	// Private is base64 of the 32-byte X25519 private key.
	Private string `json:"private"`
	// Public is base64 of the 32-byte X25519 public key.
	Public string `json:"public"`
}

// GenerateKeyPair creates a fresh X25519 key pair for WireGuard (stdlib
// crypto/ecdh — no external dependency).
func GenerateKeyPair() (KeyPair, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, fmt.Errorf("generate key: %w", err)
	}
	return KeyPair{
		Private: base64.StdEncoding.EncodeToString(key.Bytes()),
		Public:  base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()),
	}, nil
}

// PublicFromPrivate derives the public key from a base64 private key.
func PublicFromPrivate(privateB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(privateB64)
	if err != nil {
		return "", fmt.Errorf("decode private key: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("private key must be 32 bytes, got %d", len(raw))
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

// Peer is one managed WireGuard peer. On the control side it carries
// only the host's identity (the agent initiates); on the agent side the
// server's peer additionally carries Endpoint and PersistentKeepalive.
type Peer struct {
	Hostname  string
	PublicKey string
	// AllowedIPs is the /32 overlay address routed to this peer (or the
	// server's aggregate, e.g. 10.42.0.0/24, on the agent side).
	AllowedIPs string
	// Endpoint is the remote address (host:port) — set only on the
	// agent's peer entry for the control server.
	Endpoint string
	// PersistentKeepalive keeps NAT mappings alive (agent side, seconds).
	PersistentKeepalive int
}

// Backend applies peer changes to a WireGuard interface. The control
// server passes its own public key + endpoint when configuring the agent
// side of the tunnel.
type Backend interface {
	// AddPeer installs a peer on the managed interface.
	AddPeer(p Peer) error
	// RemovePeer removes a peer by public key.
	RemovePeer(publicKey string) error
	// Peers lists current peers (for status/debug).
	Peers() ([]Peer, error)
}

// Manager owns the overlay: it tracks the control server's key pair and
// routes peer changes through a Backend. When ConfPath is set it also
// maintains a wg-quick configuration file for the interface (the
// operator applies it with wg-quick/wg syncconf, or lets
// --manage-interface keep the interface in sync).
type Manager struct {
	// Interface is the WireGuard interface name (e.g. "claymod0").
	Interface string
	// ControlKeys is the control server's own WireGuard identity.
	ControlKeys KeyPair
	// ServerEndpoint is the address agents use to reach the control
	// server's WireGuard listener (host:port).
	ServerEndpoint string
	// Overlay is the interface address in CIDR form (e.g. 10.42.0.1/24).
	Overlay string
	// ListenPort is the WireGuard UDP listen port.
	ListenPort int
	// ConfPath is where the generated wg-quick config is written
	// ("" disables config persistence).
	ConfPath string
	// PeersFunc, when set, is the source of truth for the config's peer
	// list (serve wires it to the inventory). Without it the manager's
	// own peer map is used. This keeps two processes (serve and
	// `host revoke`) from resurrecting each other's changes in the file.
	PeersFunc func() ([]Peer, error)
	// Backend applies changes (real wgctrl or a fake).
	Backend Backend

	mu    sync.Mutex
	peers map[string]Peer // keyed by hostname (rebuilt from inventory on start)
}

// New creates a Manager with a fresh control-side key pair and the given
// backend.
func New(iface string, backend Backend, serverEndpoint string) (*Manager, error) {
	keys, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	return &Manager{
		Interface:      iface,
		ControlKeys:    keys,
		ServerEndpoint: serverEndpoint,
		Backend:        backend,
	}, nil
}

// NewWithKeys creates a Manager with an existing control-side key pair
// (restored from the data dir on server restart).
func NewWithKeys(iface string, keys KeyPair, backend Backend, serverEndpoint string) *Manager {
	return &Manager{
		Interface:      iface,
		ControlKeys:    keys,
		ServerEndpoint: serverEndpoint,
		Backend:        backend,
	}
}

// Enroll registers a peer on the overlay (after the bootstrap flow has
// produced the agent's WireGuard key and overlay IP) and persists the
// interface configuration.
func (m *Manager) Enroll(hostname, publicKey, overlayIP string) error {
	peer := Peer{
		Hostname:   hostname,
		PublicKey:  publicKey,
		AllowedIPs: overlayIP + "/32",
	}
	if err := m.Backend.AddPeer(peer); err != nil {
		return fmt.Errorf("wgmgr: add peer %s: %w", hostname, err)
	}
	m.mu.Lock()
	if m.peers == nil {
		m.peers = map[string]Peer{}
	}
	m.peers[hostname] = peer
	m.mu.Unlock()
	return m.persistConf()
}

// Revoke removes a peer from the overlay (part of host revocation) and
// persists the interface configuration.
func (m *Manager) Revoke(publicKey string) error {
	if publicKey == "" {
		return nil
	}
	if err := m.Backend.RemovePeer(publicKey); err != nil {
		return fmt.Errorf("wgmgr: remove peer: %w", err)
	}
	m.mu.Lock()
	for name, p := range m.peers {
		if p.PublicKey == publicKey {
			delete(m.peers, name)
		}
	}
	m.mu.Unlock()
	return m.persistConf()
}

// Resync installs a set of peers (e.g. from the inventory after a server
// restart) and persists the configuration once. Peers not in the list
// are left alone — use Revoke to remove.
func (m *Manager) Resync(peers []Peer) error {
	m.mu.Lock()
	if m.peers == nil {
		m.peers = map[string]Peer{}
	}
	for _, p := range peers {
		if err := m.Backend.AddPeer(p); err != nil {
			m.mu.Unlock()
			return fmt.Errorf("wgmgr: resync peer %s: %w", p.Hostname, err)
		}
		m.peers[p.Hostname] = p
	}
	m.mu.Unlock()
	return m.persistConf()
}

// ConfConfig builds the configuration for EnsureInterface/WriteConf
// from the manager's state (peers from PeersFunc when set).
func (m *Manager) ConfConfig() ConfConfig {
	peers := m.confPeers()
	return ConfConfig{
		Interface:  m.Interface,
		Overlay:    m.Overlay,
		ListenPort: m.ListenPort,
		PrivateKey: m.ControlKeys.Private,
		Peers:      peers,
	}
}

// confPeers resolves the peer list for the config file.
func (m *Manager) confPeers() []Peer {
	if m.PeersFunc != nil {
		peers, err := m.PeersFunc()
		if err == nil {
			return peers
		}
		// Fall through to the map on error: a transient inventory
		// failure must not stop peer management.
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	peers := make([]Peer, 0, len(m.peers))
	for _, p := range m.peers {
		peers = append(peers, p)
	}
	return peers
}

// RefreshConf rewrites the configuration file from the current peer
// source (e.g. after `host revoke` removed a host from the inventory).
func (m *Manager) RefreshConf() error {
	return m.persistConf()
}

// persistConf rewrites the wg-quick config when ConfPath is set.
func (m *Manager) persistConf() error {
	if m.ConfPath == "" {
		return nil
	}
	return WriteConf(m.ConfPath, m.ConfConfig())
}

// Peers lists current overlay peers.
func (m *Manager) Peers() ([]Peer, error) {
	return m.Backend.Peers()
}
