// Package wgmgr is the LIGHT WireGuard core shared by control server
// and agent: X25519 key generation, peer/config types and interface
// bring-up via ip/wg. The control-side peer manager (wgctrl-backed)
// lives in internal/wgmanager so the agent binary never links it.
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
