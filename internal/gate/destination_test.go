package gate_test

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/certs"
	"github.com/yuanying/natsumi-sentinel/internal/decide"
	"github.com/yuanying/natsumi-sentinel/internal/gate"
	"github.com/yuanying/natsumi-sentinel/internal/ledger"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
	"github.com/yuanying/natsumi-sentinel/internal/testca"
	direct "github.com/yuanying/natsumi-sentinel/internal/upstream"
)

const grantSurrogate = "surrogate-for-the-test-0001"

// destGrants answers destination grants from a map that a test changes.
type destGrants struct {
	mu     sync.Mutex
	grants map[string]*ledger.Grant
}

func (d *destGrants) LookupDestination(_ context.Context, source, name string) (*ledger.Grant, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.grants[name], nil
}

func (d *destGrants) set(name string, g *ledger.Grant) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if g == nil {
		delete(d.grants, name)
		return
	}
	d.grants[name] = g
}

// heldLedger holds every request asked about.
type heldLedger struct{}

func (heldLedger) LookupAll(_ context.Context, fs []ledger.Facts) ([]*ledger.Grant, error) {
	return make([]*ledger.Grant, len(fs)), nil
}

func (heldLedger) HoldAll(context.Context, []ledger.Facts, routes.ApprovalSettings) (*ledger.Approval, bool, error) {
	return &ledger.Approval{ID: "ap-write"}, true, nil
}

type grantEnv struct {
	*env
	grants   *destGrants
	upSrv    *httptest.Server
	upRoots  *x509.CertPool
	resolved map[string][]string
	mu       sync.Mutex
	upGot    []*http.Request
}

// newGrantEnv is a gate with destination grants, its own sending going to
// an upstream TLS server whose certificate is for example.com. The name
// example.com is not in the routing table.
func newGrantEnv(t *testing.T, inside ...string) *grantEnv {
	t.Helper()
	ge := &grantEnv{grants: &destGrants{grants: map[string]*ledger.Grant{}}, resolved: map[string][]string{"example.com": {"203.0.113.5"}}}
	ge.upSrv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ge.mu.Lock()
		ge.upGot = append(ge.upGot, r.Clone(context.Background()))
		ge.mu.Unlock()
		_, _ = io.WriteString(w, "from the granted upstream")
	}))
	t.Cleanup(ge.upSrv.Close)
	ge.upRoots = x509.NewCertPool()
	ge.upRoots.AddCert(ge.upSrv.Certificate())
	domains, err := direct.ParseDomains(inside)
	if err != nil {
		t.Fatal(err)
	}
	sender := direct.New(direct.Config{
		Inside:     domains,
		Surrogates: direct.NewSurrogates([]string{grantSurrogate}),
		Resolver:   resolverMap{ge: ge},
		RootCAs:    ge.upRoots,
		DialAddr: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, ge.upSrv.Listener.Addr().String())
		},
	})

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "routes.yaml"), fmt.Appendf(nil, table, 1), 0o600); err != nil {
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
	e := &env{t: t, ca: ca, log: newMemLog(), origDst: netip.MustParseAddrPort("198.51.100.99:443")}
	// authd's side: nothing a destination grant lets through may reach
	// it.
	authd := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(authd.Close)
	e.up = &upstream{srv: authd}
	tbl := decide.Table{Ledger: heldLedger{}, Destinations: &decide.DestinationGrants{Ledger: ge.grants, Inside: domains}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e.addr = ln.Addr().String()
	g := gate.New(gate.Config{
		Source: "workspace", Routes: w.Current, Decider: tbl, Connections: tbl,
		Minter: minter, Log: e.log, Upstream: e.up, Direct: sender,
		OriginalDst: func(net.Conn) (netip.AddrPort, error) {
			e.mu.Lock()
			defer e.mu.Unlock()
			return e.origDst, nil
		},
		FirstByteTimeout: time.Second,
	})
	go func() { _ = g.Serve(ln) }()
	t.Cleanup(func() { _ = g.Close() })
	ge.env = e
	return ge
}

type resolverMap struct{ ge *grantEnv }

func (r resolverMap) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.ge.mu.Lock()
	defer r.ge.mu.Unlock()
	as, ok := r.ge.resolved[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	var out []netip.Addr
	for _, a := range as {
		out = append(out, netip.MustParseAddr(a))
	}
	return out, nil
}

func (ge *grantEnv) resolveTo(name string, addrs ...string) {
	ge.mu.Lock()
	defer ge.mu.Unlock()
	ge.resolved[name] = addrs
}

func (ge *grantEnv) upstreamRequests() int {
	ge.mu.Lock()
	defer ge.mu.Unlock()
	return len(ge.upGot)
}

func inspect(id string, access ledger.Access) *ledger.Grant {
	return &ledger.Grant{ID: id, Kind: ledger.GrantDestination, Source: "workspace", Name: "example.com", Unit: ledger.UnitName, Handling: ledger.Inspect, Access: access}
}

func do(t *testing.T, c *http.Client, method, url string, header http.Header) (int, string, http.Header) {
	t.Helper()
	req, _ := http.NewRequest(method, url, nil)
	for k, vs := range header {
		req.Header[k] = vs
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

func TestARequestOnAGrantedNameIsSentByTheGateItselfAndRecordedWithWhereItWent(t *testing.T) {
	ge := newGrantEnv(t)
	ge.grants.set("example.com", inspect("gr-1", ledger.Read))
	status, body, _ := do(t, ge.client(), "GET", "https://example.com/docs?q=1", nil)
	if status != http.StatusOK || body != "from the granted upstream" {
		t.Fatalf("response = %d %q", status, body)
	}
	rec := ge.log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindHTTP })
	if rec.Verdict != audit.Allow || rec.Grant != "gr-1" || rec.Treatment != "open" || rec.Name != "example.com" ||
		!slices.Equal(rec.UpstreamAddress, []string{"203.0.113.5:443"}) || rec.Address != "198.51.100.99:443" {
		t.Errorf("record = %+v", rec)
	}
	if len(ge.up.requests()) != 0 {
		t.Error("authd was handed the request")
	}
}

func TestAWriteOnAReadOnlyGrantIsHeldForTheOwner(t *testing.T) {
	ge := newGrantEnv(t)
	ge.grants.set("example.com", inspect("gr-1", ledger.Read))
	status, _, h := do(t, ge.client(), "POST", "https://example.com/form", nil)
	if status != http.StatusForbidden || h.Get(gate.ApprovalHeader) != "ap-write" || h.Get(gate.MarkHeader) != gate.MarkAsk {
		t.Errorf("response = %d %v", status, h)
	}
	if ge.upstreamRequests() != 0 {
		t.Error("the write went out")
	}
}

func TestAWriteOnAReadWriteGrantGoesOut(t *testing.T) {
	ge := newGrantEnv(t)
	ge.grants.set("example.com", inspect("gr-1", ledger.ReadWrite))
	if status, _, _ := do(t, ge.client(), "POST", "https://example.com/form", nil); status != http.StatusOK {
		t.Errorf("status = %d", status)
	}
	if ge.upstreamRequests() != 1 {
		t.Error("the write did not go out")
	}
}

func TestARequestCarryingASurrogateToAGrantedNameIsRefusedUnsent(t *testing.T) {
	ge := newGrantEnv(t)
	ge.grants.set("example.com", inspect("gr-1", ledger.Read))
	status, body, h := do(t, ge.client(), "GET", "https://example.com/", http.Header{"Authorization": {"Bearer " + grantSurrogate}})
	if status != http.StatusForbidden || h.Get(gate.MarkHeader) != gate.MarkDeny {
		t.Errorf("response = %d %v", status, h)
	}
	if strings.Contains(body, grantSurrogate) {
		t.Error("the answer has the surrogate")
	}
	if ge.upstreamRequests() != 0 {
		t.Error("the request went out")
	}
	rec := ge.log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindHTTP })
	if rec.Verdict != audit.Deny || !strings.Contains(rec.Error, string(direct.ReasonSurrogate)) || strings.Contains(rec.Error, grantSurrogate) {
		t.Errorf("record = %+v", rec)
	}
}

func TestAGrantedOutsideNameLookedUpToAPrivateAddressIsRefusedWithTheAddresses(t *testing.T) {
	ge := newGrantEnv(t)
	ge.resolveTo("example.com", "10.0.0.1", "127.0.0.1")
	ge.grants.set("example.com", inspect("gr-1", ledger.Read))
	status, _, _ := do(t, ge.client(), "GET", "https://example.com/", nil)
	if status != http.StatusForbidden {
		t.Errorf("status = %d", status)
	}
	rec := ge.log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindHTTP })
	if rec.Verdict != audit.Deny || !strings.Contains(rec.Error, string(direct.ReasonAddressPrivate)) ||
		!slices.Equal(rec.UpstreamAddress, []string{"10.0.0.1:443", "127.0.0.1:443"}) {
		t.Errorf("record = %+v", rec)
	}
}

func TestAGrantedNameThatCannotBeReachedIsTheGatesFailure(t *testing.T) {
	ge := newGrantEnv(t)
	ge.resolveTo("example.com")
	ge.grants.set("example.com", inspect("gr-1", ledger.Read))
	status, _, h := do(t, ge.client(), "GET", "https://example.com/", nil)
	if status != http.StatusBadGateway || h.Get(gate.MarkHeader) != gate.MarkError {
		t.Errorf("response = %d %v", status, h)
	}
	rec := ge.log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindHTTP })
	if !strings.Contains(rec.Error, string(direct.ReasonUnreachable)) {
		t.Errorf("record = %+v", rec)
	}
}

func TestAnInsideNameIsMarkedInItsRecordAndSoIsOneThatWentToAPublicAddress(t *testing.T) {
	ge := newGrantEnv(t, "example.com")
	ge.grants.set("example.com", inspect("gr-1", ledger.Read))
	do(t, ge.client(), "GET", "https://example.com/", nil)
	rec := ge.log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindHTTP })
	if !strings.Contains(rec.Reason, "an inside name") || !strings.Contains(rec.Reason, "connected to a public address") {
		t.Errorf("reason = %q", rec.Reason)
	}
}

func TestARequestAfterTheGrantEndedOnTheSameConnectionIsRefused(t *testing.T) {
	ge := newGrantEnv(t)
	ge.grants.set("example.com", inspect("gr-1", ledger.Read))
	c := ge.client()
	c.Transport.(*http.Transport).DisableKeepAlives = false
	if status, _, _ := do(t, c, "GET", "https://example.com/1", nil); status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	ge.grants.set("example.com", nil)
	if status, _, _ := do(t, c, "GET", "https://example.com/2", nil); status != http.StatusForbidden {
		t.Errorf("status = %d", status)
	}
	if ge.upstreamRequests() != 1 {
		t.Errorf("upstream got %d", ge.upstreamRequests())
	}
}

func TestANameWithoutAGrantDoesNotGetPastTLS(t *testing.T) {
	ge := newGrantEnv(t)
	if _, err := ge.client().Get("https://example.com/"); err == nil {
		t.Fatal("the request went through")
	}
	rec := ge.log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindConnection })
	if rec.Verdict != audit.Deny || rec.Name != "example.com" {
		t.Errorf("record = %+v", rec)
	}
}
