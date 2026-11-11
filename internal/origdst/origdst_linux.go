package origdst

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/sys/unix"
)

// SO_ORIGINAL_DST and IP6T_SO_ORIGINAL_DST share the number 80
// (linux/netfilter_ipv4.h, linux/netfilter_ipv6/ip6_tables.h).
const soOriginalDst = 80

func lookup(c *net.TCPConn) (netip.AddrPort, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	local, _ := c.LocalAddr().(*net.TCPAddr)
	v6 := local != nil && local.IP.To4() == nil

	var (
		dst  netip.AddrPort
		serr error
	)
	err = raw.Control(func(fd uintptr) {
		if v6 {
			// IPv6MTUInfo starts with a sockaddr_in6, which is what the
			// kernel writes.
			var info *unix.IPv6MTUInfo
			info, serr = unix.GetsockoptIPv6MTUInfo(int(fd), unix.IPPROTO_IPV6, soOriginalDst)
			if serr == nil {
				port := portFromNetworkOrder(info.Addr.Port)
				dst = netip.AddrPortFrom(netip.AddrFrom16(info.Addr.Addr), port)
			}
			return
		}
		// IPv6Mreq is 20 bytes, enough to hold the sockaddr_in the
		// kernel writes: family (2), port (2, big endian), address (4).
		var mreq *unix.IPv6Mreq
		mreq, serr = unix.GetsockoptIPv6Mreq(int(fd), unix.IPPROTO_IP, soOriginalDst)
		if serr == nil {
			b := mreq.Multiaddr
			port := binary.BigEndian.Uint16(b[2:4])
			dst = netip.AddrPortFrom(netip.AddrFrom4([4]byte{b[4], b[5], b[6], b[7]}), port)
		}
	})
	if err != nil {
		return netip.AddrPort{}, err
	}
	if serr != nil {
		return netip.AddrPort{}, fmt.Errorf("SO_ORIGINAL_DST: %w", serr)
	}
	return dst, nil
}

// portFromNetworkOrder turns a port the kernel stored big endian into a
// number, whatever the host's byte order.
func portFromNetworkOrder(p uint16) uint16 {
	var b [2]byte
	binary.NativeEndian.PutUint16(b[:], p)
	return binary.BigEndian.Uint16(b[:])
}
