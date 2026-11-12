//go:build netns

// This test needs root in a network namespace of its own, where it adds
// iptables rules. Run it with `make test-netns`, never on a host's own
// namespace.

package gate_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/certs"
	"github.com/yuanying/natsumi-sentinel/internal/decide"
	"github.com/yuanying/natsumi-sentinel/internal/gate"
	"github.com/yuanying/natsumi-sentinel/internal/origdst"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
	"github.com/yuanying/natsumi-sentinel/internal/testca"
)

func iptables(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("iptables", args...).CombinedOutput(); err != nil {
		t.Fatalf("iptables %v: %v\n%s", args, err, out)
	}
}

func TestARedirectedRequestIsHandedOnToTheNameItWasOpenedFor(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("needs root in a network namespace of its own; run `make test-netns`")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "routes.yaml"), []byte("destinations:\n  - name: api.example.com\n    treatment: open\n    default: allow\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := routes.NewWatcher(dir)
	if err != nil {
		t.Fatal(err)
	}
	ca := testca.New(t)
	minter, err := certs.Load(ca.CertFile, ca.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	log := newMemLog()
	up := &upstream{}
	up.srv = newUpstreamServer(t)

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g := gate.New(gate.Config{
		Source: "workspace", Routes: w.Current, Decider: decide.Table{},
		Minter: minter, Log: log, Upstream: up, OriginalDst: origdst.Lookup,
	})
	go func() { _ = g.Serve(ln) }()
	t.Cleanup(func() { _ = g.Close() })

	// The workspace believes api.example.com is at 127.0.0.2.
	rule := []string{"OUTPUT", "-p", "tcp", "-d", "127.0.0.2", "--dport", "443", "-j", "REDIRECT", "--to-ports", fmt.Sprint(ln.Addr().(*net.TCPAddr).Port)}
	iptables(t, append([]string{"-t", "nat", "-A"}, rule...)...)
	t.Cleanup(func() { iptables(t, append([]string{"-t", "nat", "-D"}, rule...)...) })

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp4", "127.0.0.2:443")
			},
			TLSClientConfig: &tls.Config{RootCAs: ca.Pool()},
		},
	}
	resp, err := client.Get("https://api.example.com/hello")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated || string(body) != "from upstream" {
		t.Errorf("response = %d %q", resp.StatusCode, body)
	}
	seen := up.requests()
	if len(seen) != 1 || seen[0].URL.String() != "https://api.example.com:443/hello" {
		t.Fatalf("handed on: %v", seen)
	}
	rec := log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindHTTP })
	if rec.Address != "127.0.0.2:443" || rec.Name != "api.example.com" || rec.Status != 201 {
		t.Errorf("record = %+v", rec)
	}
}

func newUpstreamServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "from upstream")
	}))
	t.Cleanup(srv.Close)
	return srv
}

// ipv6Redirect makes ip6tables redirect tcp to dst on the loopback to port,
// or skips the test where the kernel has no IPv6 NAT.
func ipv6Redirect(t *testing.T, dst string, dport, port int) {
	t.Helper()
	if out, err := exec.Command("ip6tables", "-t", "nat", "-L", "OUTPUT").CombinedOutput(); err != nil {
		t.Skipf("skipped: no IPv6 NAT here (ip6tables -t nat: %v: %s)", err, out)
	}
	if out, err := exec.Command("ip", "-6", "addr", "add", dst+"/128", "dev", "lo", "nodad").CombinedOutput(); err != nil {
		t.Skipf("skipped: no IPv6 on the loopback (%v: %s)", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "-6", "addr", "del", dst+"/128", "dev", "lo").Run() })
	rule := []string{"OUTPUT", "-p", "tcp", "-d", dst, "--dport", fmt.Sprint(dport), "-j", "REDIRECT", "--to-ports", fmt.Sprint(port)}
	if out, err := exec.Command("ip6tables", append([]string{"-t", "nat", "-A"}, rule...)...).CombinedOutput(); err != nil {
		t.Fatalf("ip6tables %v: %v\n%s", rule, err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip6tables", append([]string{"-t", "nat", "-D"}, rule...)...).Run() })
}

// ipv6Gate is a gate listening on the IPv6 loopback, with ip6tables
// redirecting 2001:db8::3 port 443 to it.
func ipv6Gate(t *testing.T) (*testca.CA, *memLog, *upstream) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("needs root in a network namespace of its own; run `make test-netns`")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "routes.yaml"), []byte("destinations:\n  - name: api.example.com\n    treatment: open\n    default: allow\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := routes.NewWatcher(dir)
	if err != nil {
		t.Fatal(err)
	}
	ca := testca.New(t)
	minter, err := certs.Load(ca.CertFile, ca.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	log := newMemLog()
	up := &upstream{}
	up.srv = newUpstreamServer(t)
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("skipped: no IPv6 loopback here: %v", err)
	}
	g := gate.New(gate.Config{
		Source: "workspace", Routes: w.Current, Decider: decide.Table{},
		Minter: minter, Log: log, Upstream: up, OriginalDst: origdst.Lookup,
	})
	go func() { _ = g.Serve(ln) }()
	t.Cleanup(func() { _ = g.Close() })
	ipv6Redirect(t, "2001:db8::3", 443, ln.Addr().(*net.TCPAddr).Port)
	return ca, log, up
}

func TestARedirectedIPv6RequestIsHandedOnToTheNameItWasOpenedFor(t *testing.T) {
	ca, log, up := ipv6Gate(t)
	// The workspace was told api.example.com is at 2001:db8::3.
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp6", "[2001:db8::3]:443")
			},
			TLSClientConfig: &tls.Config{RootCAs: ca.Pool()},
		},
	}
	resp, err := client.Get("https://api.example.com/hello")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated || string(body) != "from upstream" {
		t.Errorf("response = %d %q", resp.StatusCode, body)
	}
	// Handed on by the name, not the address it was going to.
	seen := up.requests()
	if len(seen) != 1 || seen[0].URL.String() != "https://api.example.com:443/hello" {
		t.Fatalf("handed on: %v", seen)
	}
	rec := log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindHTTP })
	if rec.Address != "[2001:db8::3]:443" || rec.Name != "api.example.com" || rec.Status != 201 {
		t.Errorf("record = %+v", rec)
	}
}

func TestARedirectedIPv6ConnectionToAnAddressWithoutANameIsRefused(t *testing.T) {
	ca, log, up := ipv6Gate(t)
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.Pool()}},
	}
	if resp, err := client.Get("https://[2001:db8::3]/hello"); err == nil {
		_ = resp.Body.Close()
		t.Fatalf("an IPv6 address written straight got %d, want the handshake cut", resp.StatusCode)
	}
	if seen := up.requests(); len(seen) != 0 {
		t.Fatalf("handed on: %v", seen)
	}
	rec := log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindConnection })
	if rec.Address != "[2001:db8::3]:443" || rec.Verdict != audit.Deny || rec.Reason != "TLS without SNI; the gate decides by name" {
		t.Errorf("record = %+v", rec)
	}
}
