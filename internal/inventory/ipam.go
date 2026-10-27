package inventory

import (
	"fmt"
	"net"
	"net/netip"
)

// ipam allocates addresses from the agent network's IPv4 range. The
// allocations themselves live in the inventory DB (see ip_allocations);
// this helper only decides which address is free.
//
// Address layout (routed overlays): base = network address, base+1 = the
// CONTROL SERVER's overlay address (reserved — never allocated to a
// host), hosts get base+2 .. broadcast-1. Reserving base+1 matters: a
// host record holding the server's address would make wgmgr route the
// server's own overlay address to a peer.
//
// Loopback networks (127/8) are exempt: there is no distinct server
// address there (everything shares 127.0.0.1 and ports distinguish
// processes), and other 127.x addresses are not dialable on macOS. The
// reservation only exists for real overlays where server and hosts have
// distinct addresses.
type ipam struct {
	network       netip.Prefix
	base          netip.Addr // network address
	last          netip.Addr // last usable address (before broadcast)
	reserveServer bool
}

func newIPAM(cidr string) (*ipam, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse agent network: %w", err)
	}
	prefix = prefix.Masked()
	if !prefix.Addr().Is4() {
		return nil, fmt.Errorf("agent network must be IPv4: %s", cidr)
	}
	// Usable range: skip the network address and the broadcast address.
	base := prefix.Addr()
	last := lastAddr(prefix)
	if prefix.Bits() >= 31 {
		return nil, fmt.Errorf("agent network too small: %s", cidr)
	}
	return &ipam{
		network: prefix,
		base:    base,
		last:    last,
		// Routed overlays reserve base+1 for the control server;
		// loopback dev networks share 127.0.0.1 for everything.
		reserveServer: !prefix.Addr().IsLoopback(),
	}, nil
}

// serverAddr returns the control-server overlay address (base+1).
func (i *ipam) serverAddr() netip.Addr { return i.base.Next() }

// firstHostAddr returns the first address allocatable to a host
// (base+2 on routed overlays where base+1 is reserved, else base+1).
func (i *ipam) firstHostAddr() netip.Addr {
	if i.reserveServer {
		return i.base.Next().Next()
	}
	return i.base.Next()
}

// inRange reports whether ip is allocatable to a host in this network.
// The reserved server address is NOT in range.
func (i *ipam) inRange(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	if !addr.Is4() {
		return false
	}
	if i.reserveServer && addr == i.serverAddr() {
		return false
	}
	return i.cmp(addr, i.firstHostAddr()) >= 0 && i.cmp(addr, i.last) <= 0
}

// isServerAddr reports whether ip is the reserved control-server
// address (only meaningful on routed overlays).
func (i *ipam) isServerAddr(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	return err == nil && i.reserveServer && addr == i.serverAddr()
}

// nextFree returns the lowest-addressed free host IP, or "" when
// exhausted. Freed (unallocated) addresses are naturally reusable; the
// reserved server address is never returned.
func (i *ipam) nextFree(used map[string]bool) string {
	for addr := i.firstHostAddr(); i.cmp(addr, i.last) <= 0; addr = addr.Next() {
		if !used[addr.String()] {
			return addr.String()
		}
	}
	return ""
}

// cmp orders two IPv4 addresses (-1, 0, 1).
func (i *ipam) cmp(a, b netip.Addr) int {
	av := a.As4()
	bv := b.As4()
	for k := 0; k < 4; k++ {
		if av[k] < bv[k] {
			return -1
		}
		if av[k] > bv[k] {
			return 1
		}
	}
	return 0
}

func lastAddr(p netip.Prefix) netip.Addr {
	base := p.Masked().Addr()
	ip := net.IP(base.AsSlice()).To4()
	mask := net.CIDRMask(p.Bits(), 32)
	for k := range ip {
		ip[k] |= ^mask[k]
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return base
	}
	// Skip the broadcast address.
	return addr.Prev()
}
