// Package peercred listens on a Unix socket and hands on only the connections
// whose peer runs as one allowed UID.
//
// The parts of natsumi-sentinel talk to each other over Unix sockets and hold
// no shared secret between them (docs/adr/0001). What tells a caller apart is
// the UID the kernel reports for the other end of the connection
// (SO_PEERCRED), so the socket file itself is left open to every UID: the
// check is the UID, not the file's mode.
package peercred

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"time"
)

// Listen listens on a Unix socket at path. Accept returns only connections
// whose peer's UID is allowedUID. Any other connection is closed at once,
// after onReject (if not nil) is told the UID it came from, or -1 when the
// UID could not be read.
//
// A socket file left at path by a process that is gone is replaced. Anything
// else at path, or a socket that something still listens on, is left alone
// and Listen fails.
func Listen(path string, allowedUID int, onReject func(uid int)) (net.Listener, error) {
	if err := removeStaleSocket(path); err != nil {
		return nil, err
	}
	ul, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o666); err != nil {
		_ = ul.Close()
		return nil, err
	}
	return &listener{UnixListener: ul, allowed: allowedUID, onReject: onReject}, nil
}

func removeStaleSocket(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode().Type() != fs.ModeSocket {
		return fmt.Errorf("%s exists and is not a socket", path)
	}
	if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
		_ = c.Close()
		return fmt.Errorf("%s is in use by another listener", path)
	}
	return os.Remove(path)
}

type listener struct {
	*net.UnixListener
	allowed  int
	onReject func(uid int)
}

// Accept waits for the next connection from the allowed UID.
func (l *listener) Accept() (net.Conn, error) {
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			return nil, err
		}
		uid, err := peerUID(c)
		if err == nil && uid == l.allowed {
			return c, nil
		}
		if err != nil {
			uid = -1
		}
		if l.onReject != nil {
			l.onReject(uid)
		}
		_ = c.Close()
	}
}
