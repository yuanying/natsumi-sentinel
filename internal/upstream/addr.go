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
	// sixToFour (RFC 3056) carries an IPv4 address in bits 16 to 47, and
	// compatible (the IPv4-compatible form RFC 4291 deprecates) in its
	// last 32 bits. Either is taken as the IPv4 address it carries, so
	// that no form of a loopback or private IPv4 address passes as a
	// public IPv6 one.
	sixToFour  = netip.MustParsePrefix("2002::/16")
	compatible = netip.MustParsePrefix("::/96")
	// localNAT64 (RFC 8215) is a site's own translator: what it reaches
	// depends on the site, so it is private.
	localNAT64 = netip.MustParsePrefix("64:ff9b:1::/48")
	// discard (RFC 6666) reaches no one.
	discard = netip.MustParsePrefix("100::/64")
)

// carried is the IPv4 address a carries in one of the IPv6 forms that
// carry one, or a itself.
func carried(a netip.Addr) netip.Addr {
	a = a.Unmap()
	if !a.Is6() {
		return a
	}
	b := a.As16()
	switch {
	case nat64.Contains(a), compatible.Contains(a):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	case sixToFour.Contains(a):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]})
	}
	return a
}

// classify tells what addr is. extra are more private ranges, for a
// cluster whose ranges are outside the usual ones.
func classify(addr netip.Addr, extra []netip.Prefix) class {
	a := carried(addr)
	switch {
	case !a.IsValid(),
		a.IsLoopback(), a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast(),
		a.IsInterfaceLocalMulticast(), a.IsMulticast(), a.IsUnspecified():
		return local
	case a.Is4() && (thisNetwork.Contains(a) || reserved.Contains(a)):
		// 255.255.255.255 is in reserved.
		return local
	case discard.Contains(a):
		return local
	case a.IsPrivate(), sharedSpace.Contains(a), localNAT64.Contains(a):
		return private
	}
	for _, p := range extra {
		if p.Contains(a) {
			return private
		}
	}
	return public
}
