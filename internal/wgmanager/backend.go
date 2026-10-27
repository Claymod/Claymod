package wgmanager

import (
	"fmt"
	"net"
	"sync"

	"github.com/claymod/claymod/internal/wgmgr"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// parseAllowedIP parses "10.42.0.7/32" (or a bare IP) into a CIDR.
func parseAllowedIP(s string) (net.IP, net.IPNet, error) {
	if s == "" {
		return net.IP{}, net.IPNet{}, fmt.Errorf("allowed IP is required")
	}
	ip, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		// Bare IP: default to /32.
		ip = net.ParseIP(s)
		if ip == nil {
			return net.IP{}, net.IPNet{}, fmt.Errorf("parse allowed IP %q: %w", s, err)
		}
		ipNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
	}
	return ip, *ipNet, nil
}

// FakeBackend is an in-memory Backend for tests and root-less runs. It
// tracks peers exactly like a real interface would.
type FakeBackend struct {
	mu    sync.Mutex
	peers map[string]wgmgr.Peer // keyed by public key
}

// NewFakeBackend creates an empty fake.
func NewFakeBackend() *FakeBackend {
	return &FakeBackend{peers: map[string]wgmgr.Peer{}}
}

// AddPeer implements Backend.
func (f *FakeBackend) AddPeer(p wgmgr.Peer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p.PublicKey == "" {
		return fmt.Errorf("peer public key is required")
	}
	f.peers[p.PublicKey] = p
	return nil
}

// RemovePeer implements Backend.
func (f *FakeBackend) RemovePeer(publicKey string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.peers[publicKey]; !ok {
		return fmt.Errorf("peer %s not found", publicKey)
	}
	delete(f.peers, publicKey)
	return nil
}

// Peers implements Backend.
func (f *FakeBackend) Peers() ([]wgmgr.Peer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]wgmgr.Peer, 0, len(f.peers))
	for _, p := range f.peers {
		out = append(out, p)
	}
	return out, nil
}

// WgctrlBackend drives a real WireGuard interface through wgctrl. The
// interface itself (e.g. claymod0) is created outside — see
// docs/enrollment.md; this backend only manages peers on it.
type WgctrlBackend struct {
	// Interface is the WireGuard device name.
	Interface string
}

// NewWgctrlBackend targets the named interface.
func NewWgctrlBackend(iface string) *WgctrlBackend {
	return &WgctrlBackend{Interface: iface}
}

// AddPeer implements Backend: it merges the peer onto the device,
// replacing only this peer's allowed IPs.
func (w *WgctrlBackend) AddPeer(p wgmgr.Peer) error {
	key, err := wgtypes.ParseKey(p.PublicKey)
	if err != nil {
		return fmt.Errorf("parse peer key: %w", err)
	}
	_, ipNet, err := parseAllowedIP(p.AllowedIPs)
	if err != nil {
		return err
	}
	client, err := openWgctrl()
	if err != nil {
		return err
	}
	defer client.Close()
	return client.ConfigureDevice(w.Interface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{
			PublicKey:         key,
			ReplaceAllowedIPs: true,
			AllowedIPs:        []net.IPNet{ipNet},
		}},
	})
}

// RemovePeer implements Backend (Remove=true drops the peer entirely).
func (w *WgctrlBackend) RemovePeer(publicKey string) error {
	key, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return fmt.Errorf("parse peer key: %w", err)
	}
	client, err := openWgctrl()
	if err != nil {
		return err
	}
	defer client.Close()
	return client.ConfigureDevice(w.Interface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{
			PublicKey: key,
			Remove:    true,
		}},
	})
}

// Peers implements Backend.
func (w *WgctrlBackend) Peers() ([]wgmgr.Peer, error) {
	client, err := openWgctrl()
	if err != nil {
		return nil, err
	}
	defer client.Close()
	dev, err := client.Device(w.Interface)
	if err != nil {
		return nil, fmt.Errorf("wgctrl: device %s: %w", w.Interface, err)
	}
	out := make([]wgmgr.Peer, 0, len(dev.Peers))
	for _, p := range dev.Peers {
		allowed := ""
		if len(p.AllowedIPs) > 0 {
			allowed = p.AllowedIPs[0].String()
		}
		out = append(out, wgmgr.Peer{
			Hostname:   "", // wgctrl cannot map hostnames; the inventory holds that
			PublicKey:  p.PublicKey.String(),
			AllowedIPs: allowed,
		})
	}
	return out, nil
}

// openWgctrl wraps wgctrl.New for testability.
var openWgctrl = func() (wgctrlClient, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctrl: %w", err)
	}
	return client, nil
}

// wgctrlClient is the subset of *wgctrl.Client used here.
type wgctrlClient interface {
	ConfigureDevice(name string, cfg wgtypes.Config) error
	Device(name string) (*wgtypes.Device, error)
	Close() error
}
