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
