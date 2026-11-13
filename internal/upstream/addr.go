package upstream

import "net/netip"

// class is what an address is to a connection the gate makes itself
// (docs/destination-grants.md "関所が直に送る").
type class int

const (
	// public may be connected to by any name.
	public class = iota
	// private (the LAN, and the cluster's Service and Pod addresses) may
	// be connected to by an inside name only.
	private
	// local is never connected to: loopback and link-local (the metadata
	// endpoint among them), and the addresses that are no one's to reach
	// (unspecified, multicast, broadcast, reserved).
	local
)

var (
	// thisNetwork, broadcast and reserved are the IPv4 addresses that
	// netip does not name and that no upstream has.
	thisNetwork = netip.MustParsePrefix("0.0.0.0/8")
	reserved    = netip.MustParsePrefix("240.0.0.0/4")
	// sharedSpace (RFC 6598) is behind a carrier's NAT, and clusters
	// take their Pod and Service ranges from it.
	sharedSpace = netip.MustParsePrefix("100.64.0.0/10")
	// nat64 (RFC 6052) carries an IPv4 address in its last 32 bits; the
	// IPv4 address is what it reaches.
	nat64 = netip.MustParsePrefix("64:ff9b::/96")
)

// classify tells what addr is. extra are more private ranges, for a
// cluster whose ranges are outside the usual ones.
func classify(addr netip.Addr, extra []netip.Prefix) class {
	a := addr.Unmap()
	if a.Is6() && nat64.Contains(a) {
		b := a.As16()
		a = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	switch {
	case !a.IsValid(),
		a.IsLoopback(), a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast(),
		a.IsInterfaceLocalMulticast(), a.IsMulticast(), a.IsUnspecified():
		return local
	case a.Is4() && (thisNetwork.Contains(a) || reserved.Contains(a)):
		// 255.255.255.255 is in reserved.
		return local
	case a.IsPrivate(), sharedSpace.Contains(a):
		return private
	}
	for _, p := range extra {
		if p.Contains(a) {
			return private
		}
	}
	return public
}
