package inventory

import (
	"fmt"
	"net"
	"net/netip"
)

// ipam allocates addresses from the agent network's IPv4 range. The
// allocations themselves live in the inventory DB (see ip_allocations);
// this helper only decides which address is free.
type ipam struct {
	network netip.Prefix
	base    netip.Addr // network address
	last    netip.Addr // last usable address
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
	return &ipam{network: prefix, base: base, last: last}, nil
}

// inRange reports whether ip is an allocatable address in the network.
func (i *ipam) inRange(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	if !addr.Is4() {
		return false
	}
	return i.cmp(addr, i.base) > 0 && i.cmp(addr, i.last) <= 0
}

// nextFree returns the lowest-addressed free IP, or "" when exhausted.
// Freed (unallocated) addresses are naturally reusable.
func (i *ipam) nextFree(used map[string]bool) string {
	for addr := i.base.Next(); i.cmp(addr, i.last) <= 0; addr = addr.Next() {
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
