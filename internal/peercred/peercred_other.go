//go:build !linux

package peercred

import (
	"errors"
	"net"
)

// peerUID cannot read the peer's UID outside Linux, so every connection is
// refused there: both programs only run on Linux.
func peerUID(*net.UnixConn) (int, error) {
	return 0, errors.New("reading the peer's UID is only supported on Linux")
}
