// Package e2e_test runs the gate and authd together, joined by authd's real
// Unix socket, in front of a fake upstream: what the workspace sends goes
// through the gate's decision and record, is handed to authd, has its
// surrogate swapped and reaches the upstream.
package e2e_test

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/authd"
	"github.com/yuanying/natsumi-sentinel/internal/authdclient"
	"github.com/yuanying/natsumi-sentinel/internal/certs"
	"github.com/yuanying/natsumi-sentinel/internal/decide"
	"github.com/yuanying/natsumi-sentinel/internal/gate"
	"github.com/yuanying/natsumi-sentinel/internal/peercred"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
	"github.com/yuanying/natsumi-sentinel/internal/testca"
)

const (
	surrogate = "surrogate-for-the-e2e-test-0123"
	realKey   = "real-key-for-the-e2e-test-only"
)

// The fake upstream's certificate (httptest's) is for example.com, so that
// is the upstream's name. unregistered.example.com is open in the gate but
// not registered in authd.
const routesYAML = `
destinations:
  - name: example.com
    treatment: open
    default: allow
  - name: unregistered.example.com
    treatment: open
    default: allow
`

type world struct {
	t   *testing.T
	ca  *testca.CA
	log *audit.Log

	mu   sync.Mutex
	seen []*http.Request

	gateAddr string
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{t: t, ca: testca.New(t)}

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w.mu.Lock()
		w.seen = append(w.seen, r.Clone(context.Background()))
		w.mu.Unlock()
		rw.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(rw, "from upstream")
	}))
	t.Cleanup(upstream.Close)

	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	upstreamCA := write("upstream-ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw})))
	keyFile := write("key", realKey)
	reg := write("authd.yaml", fmt.Sprintf(`upstreams:
  - name: example.com
    ports: [443]
    ca_file: %s
credentials:
  - surrogate: %s
    key_file: %s
    upstreams: [example.com]
    places:
      - type: bearer
`, upstreamCA, surrogate, keyFile))
	cfg, err := authd.LoadConfig(reg)
	if err != nil {
		t.Fatal(err)
	}
	upstreamAddr := upstream.Listener.Addr().String()
	handler, err := authd.NewHandler(cfg, authd.Options{
		Logger: slog.New(slog.DiscardHandler),
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, upstreamAddr)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	sockDir, err := os.MkdirTemp("", "e2e")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "authd.sock")
	l, err := peercred.Listen(sock, os.Getuid(), nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	tr := authdclient.NewTransport(sock)
	t.Cleanup(tr.CloseIdleConnections)

	routesDir := filepath.Join(dir, "routes")
	if err := os.Mkdir(routesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	write("routes/routes.yaml", routesYAML)
	watcher, err := routes.NewWatcher(routesDir)
	if err != nil {
		t.Fatal(err)
	}
	minter, err := certs.Load(w.ca.CertFile, w.ca.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	w.log, err = audit.Open(filepath.Join(dir, "audit.db"), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.log.Close() })

	g := gate.New(gate.Config{
		Source:   "workspace",
		Routes:   watcher.Current,
		Decider:  decide.Defaults{},
		Minter:   minter,
		Log:      w.log,
		Upstream: tr,
		OriginalDst: func(net.Conn) (netip.AddrPort, error) {
			return netip.MustParseAddrPort("192.0.2.10:443"), nil
		},
		Logger: slog.New(slog.DiscardHandler),
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	w.gateAddr = ln.Addr().String()
	go func() { _ = g.Serve(ln) }()
	t.Cleanup(func() { _ = g.Close() })
	return w
}

// client is the workspace's tool: it talks to the real URL, and every
// connection lands on the gate.
func (w *world) client() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, w.gateAddr)
			},
			TLSClientConfig:   &tls.Config{RootCAs: w.ca.Pool()},
			DisableKeepAlives: true,
		},
		Timeout: 10 * time.Second,
	}
}

func (w *world) do(method, url, body string) (*http.Response, string) {
	w.t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		w.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+surrogate)
	resp, err := w.client().Do(req)
	if err != nil {
		w.t.Fatalf("%s %s: %v", method, url, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(b)
}

func (w *world) upstreamSaw() []*http.Request {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]*http.Request(nil), w.seen...)
}

// lastRecord is the newest http record, once it is finished.
func (w *world) lastRecord() *audit.Record {
	w.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		recs, err := w.log.List(context.Background(), audit.Query{Kind: audit.KindHTTP, Limit: 1})
		if err != nil {
			w.t.Fatal(err)
		}
		if len(recs) == 1 && recs[0].Finished {
			return recs[0]
		}
		if time.Now().After(deadline) {
			w.t.Fatalf("no finished http record: %+v", recs)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestAnAllowedRequestGoesThroughAuthdWithTheRealKeyToTheUpstream(t *testing.T) {
	w := newWorld(t)
	// The tool writes the Host without the port, as most do for 443.
	resp, body := w.do("POST", "https://example.com/repos/o/r/issues", `{"title":"hi"}`)
	if resp.StatusCode != http.StatusCreated || body != "from upstream" {
		t.Fatalf("response = %d %q, want the upstream's 201", resp.StatusCode, body)
	}
	seen := w.upstreamSaw()
	if len(seen) != 1 {
		t.Fatalf("the upstream saw %d requests, want 1", len(seen))
	}
	if got := seen[0].Header.Get("Authorization"); got != "Bearer "+realKey {
		t.Errorf("the upstream got Authorization %q, want the real key", got)
	}
	rec := w.lastRecord()
	if rec.Verdict != audit.Allow || rec.Status != http.StatusCreated || rec.Request == nil || rec.Request.Text != `{"title":"hi"}` {
		t.Errorf("record = %+v", rec)
	}
}

func TestARefusalByAuthdIsRecordedWithItsReasonAndNothingReachesTheUpstream(t *testing.T) {
	w := newWorld(t)
	resp, body := w.do("GET", "https://unregistered.example.com/", "")
	if resp.StatusCode != http.StatusBadGateway || resp.Header.Get(gate.MarkHeader) != gate.MarkError {
		t.Fatalf("response = %d %q, want the gate's 502", resp.StatusCode, body)
	}
	if n := len(w.upstreamSaw()); n != 0 {
		t.Errorf("the upstream saw %d requests, want none", n)
	}
	rec := w.lastRecord()
	if rec.AuthdReason != string(authdclient.ReasonUpstreamNotRegistered) {
		t.Errorf("record = %+v, want authd's reason", rec)
	}
}
