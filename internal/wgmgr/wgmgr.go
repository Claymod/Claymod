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

// Peer is one managed WireGuard peer on the control side.
type Peer struct {
	Hostname  string
	PublicKey string
	// AllowedIPs is the /32 overlay address routed to this peer.
	AllowedIPs string
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
// routes peer changes through a Backend.
type Manager struct {
	// Interface is the WireGuard interface name (e.g. "claymod0").
	Interface string
	// ControlKeys is the control server's own WireGuard identity.
	ControlKeys KeyPair
	// ServerEndpoint is the address agents use to reach the control
	// server's WireGuard listener (host:port).
	ServerEndpoint string
	// Backend applies changes (real wgctrl or a fake).
	Backend Backend
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
// produced the agent's WireGuard key and overlay IP).
func (m *Manager) Enroll(hostname, publicKey, overlayIP string) error {
	if err := m.Backend.AddPeer(Peer{
		Hostname:   hostname,
		PublicKey:  publicKey,
		AllowedIPs: overlayIP + "/32",
	}); err != nil {
		return fmt.Errorf("wgmgr: add peer %s: %w", hostname, err)
	}
	return nil
}

// Revoke removes a peer from the overlay (part of host revocation).
func (m *Manager) Revoke(publicKey string) error {
	if publicKey == "" {
		return nil
	}
	if err := m.Backend.RemovePeer(publicKey); err != nil {
		return fmt.Errorf("wgmgr: remove peer: %w", err)
	}
	return nil
}

// Peers lists current overlay peers.
func (m *Manager) Peers() ([]Peer, error) {
	return m.Backend.Peers()
}
