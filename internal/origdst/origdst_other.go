//go:build !linux

package origdst

import (
	"errors"
	"net"
	"net/netip"
)

func lookup(*net.TCPConn) (netip.AddrPort, error) {
	return netip.AddrPort{}, errors.New("SO_ORIGINAL_DST is only on Linux")
}
