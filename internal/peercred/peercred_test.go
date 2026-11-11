package peercred_test

import (
	"bufio"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/peercred"
)

// socketPath returns a path for a Unix socket. A socket's path has to fit in
// about a hundred bytes, which t.TempDir() can overrun with a long test name.
func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "peercred")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

// echoOnce accepts connections and writes back the first line of each.
func echoOnce(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = c.Close() }()
			line, err := bufio.NewReader(c).ReadString('\n')
			if err != nil {
				return
			}
			_, _ = io.WriteString(c, line)
		}()
	}
}

func talk(t *testing.T, path string) (string, error) {
	t.Helper()
	c, err := net.Dial("unix", path)
	if err != nil {
		return "", err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, "hello\n"); err != nil {
		return "", err
	}
	return bufio.NewReader(c).ReadString('\n')
}

func TestAConnectionFromTheAllowedUIDIsAccepted(t *testing.T) {
	path := socketPath(t)
	l, err := peercred.Listen(path, os.Getuid(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go echoOnce(l)

	got, err := talk(t, path)
	if err != nil {
		t.Fatalf("talking to the socket: %v", err)
	}
	if got != "hello\n" {
		t.Errorf("echo = %q, want %q", got, "hello\n")
	}
}

func TestAConnectionFromAnotherUIDIsClosedBeforeItIsHandedOn(t *testing.T) {
	path := socketPath(t)
	rejected := make(chan int, 1)
	l, err := peercred.Listen(path, os.Getuid()+1, func(uid int) { rejected <- uid })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	accepted := make(chan struct{}, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			accepted <- struct{}{}
			_ = c.Close()
		}
	}()

	got, err := talk(t, path)
	if err == nil {
		t.Fatalf("talking to the socket gave %q, want the connection closed", got)
	}
	select {
	case <-accepted:
		t.Fatal("the connection was handed to Accept's caller")
	case <-time.After(100 * time.Millisecond):
	}
	select {
	case uid := <-rejected:
		if uid != os.Getuid() {
			t.Errorf("rejected UID = %d, want %d", uid, os.Getuid())
		}
	case <-time.After(5 * time.Second):
		t.Error("onReject was not called")
	}
}

func TestTheListenerKeepsAcceptingAfterRefusingAConnection(t *testing.T) {
	path := socketPath(t)
	l, err := peercred.Listen(path, os.Getuid()+1, nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := l.Accept()
		done <- err
	}()
	if _, err := talk(t, path); err == nil {
		t.Fatal("the first connection was not refused")
	}
	if _, err := talk(t, path); err == nil {
		t.Fatal("the second connection was not refused")
	}
	_ = l.Close()
	if err := <-done; !errors.Is(err, net.ErrClosed) {
		t.Errorf("Accept after Close = %v, want net.ErrClosed", err)
	}
}

func TestAStaleSocketFileIsReplaced(t *testing.T) {
	path := socketPath(t)
	old, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	// Leave the file behind, as a process that was killed would.
	old.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = old.Close()

	l, err := peercred.Listen(path, os.Getuid(), nil)
	if err != nil {
		t.Fatalf("Listen over a stale socket: %v", err)
	}
	_ = l.Close()
}

func TestAPathThatIsNotASocketIsLeftAloneAndListenFails(t *testing.T) {
	path := socketPath(t)
	if err := os.WriteFile(path, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if l, err := peercred.Listen(path, os.Getuid(), nil); err == nil {
		_ = l.Close()
		t.Fatal("Listen over a regular file succeeded")
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "keep me" {
		t.Errorf("the file was changed: %q, %v", b, err)
	}
}

func TestTheSocketCanBeOpenedByAnyUIDSoThatTheCheckIsTheUIDNotTheFileMode(t *testing.T) {
	path := socketPath(t)
	l, err := peercred.Listen(path, os.Getuid(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o666 {
		t.Errorf("socket mode = %o, want 666", got)
	}
}
