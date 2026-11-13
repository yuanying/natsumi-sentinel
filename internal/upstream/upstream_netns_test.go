//go:build netns

// These tests need root in a network namespace of their own, where they
// put an address on the loopback interface and listen on port 443. Run
// them with `make test-netns`, never on a host's own namespace.

package upstream_test

import (
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/upstream"
)

// listen443 serves TLS on addr:443 in the namespace, with a certificate
// for example.com, and counts the connections it takes.
func listen443(t *testing.T, addr string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("needs root in a network namespace of its own; run `make test-netns`")
	}
	if a := netip.MustParseAddr(addr); !a.IsLoopback() {
		if out, err := exec.Command("ip", "addr", "add", addr+"/32", "dev", "lo").CombinedOutput(); err != nil {
			t.Fatalf("ip addr add: %v\n%s", err, out)
		}
		t.Cleanup(func() { _ = exec.Command("ip", "addr", "del", addr+"/32", "dev", "lo").Run() })
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(addr, "443"))
	if err != nil {
		t.Fatal(err)
	}
	accepted := new(atomic.Int32)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello from "+r.Host)
	}))
	srv.Listener = &countingListener{Listener: ln, n: accepted}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, accepted
}

type countingListener struct {
	net.Listener
	n *atomic.Int32
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.n.Add(1)
	}
	return c, err
}

// realSender dials for real, with only the names looked up made up.
func realSender(srv *httptest.Server, addrs map[string][]string) *upstream.Sender {
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	return upstream.New(upstream.Config{Resolver: &fakeResolver{addrs: addrs}, RootCAs: roots})
}

func TestARequestGoesOutOverARealConnectionToTheAddressLookedUp(t *testing.T) {
	srv, _ := listen443(t, "192.0.2.10")
	s := realSender(srv, map[string][]string{"example.com": {"192.0.2.10"}})
	ctx, rep := upstream.WithReport(context.Background())
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
	resp, err := s.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "hello from example.com" {
		t.Errorf("body = %q", body)
	}
	if rep.Address != netip.MustParseAddrPort("192.0.2.10:443") {
		t.Errorf("address = %s", rep.Address)
	}
}

func TestAPassthroughDialMakesARealConnection(t *testing.T) {
	srv, accepted := listen443(t, "192.0.2.11")
	s := realSender(srv, map[string][]string{"example.com": {"192.0.2.11"}})
	c, err := s.Dial(context.Background(), "example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if c.Report.Address != netip.MustParseAddrPort("192.0.2.11:443") {
		t.Errorf("address = %s", c.Report.Address)
	}
	time.Sleep(100 * time.Millisecond)
	if n := accepted.Load(); n != 1 {
		t.Errorf("accepted %d connections, want 1", n)
	}
}

func TestNothingIsConnectedToALoopbackAddressThatListens(t *testing.T) {
	srv, accepted := listen443(t, "127.0.0.1")
	s := realSender(srv, map[string][]string{"example.com": {"127.0.0.1"}})
	if _, err := s.Dial(context.Background(), "example.com", 443); reason(t, err) != upstream.ReasonAddressLocal {
		t.Errorf("err = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
	if _, err := s.RoundTrip(req); reason(t, err) != upstream.ReasonAddressLocal {
		t.Errorf("err = %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if n := accepted.Load(); n != 0 {
		t.Errorf("accepted %d connections, want none", n)
	}
}
