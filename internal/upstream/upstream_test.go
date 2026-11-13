package upstream_test

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/yuanying/natsumi-sentinel/internal/upstream"
)

const surrogate = "surrogate-0123456789abcdef"

// fakeResolver answers names from a map, and counts the lookups.
type fakeResolver struct {
	mu      sync.Mutex
	addrs   map[string][]string
	lookups int
}

func (f *fakeResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookups++
	if network != "ip" {
		return nil, errors.New("asked for " + network + ", want both families")
	}
	as, ok := f.addrs[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	var out []netip.Addr
	for _, a := range as {
		out = append(out, netip.MustParseAddr(a))
	}
	return out, nil
}

// env is an upstream (an httptest TLS server, whose certificate is for
// example.com) reached by whatever address the sender dials.
type env struct {
	srv      *httptest.Server
	resolver *fakeResolver
	sender   *upstream.Sender

	mu     sync.Mutex
	dialed []string
	got    []*http.Request
	// refuse lists the addresses whose dials fail.
	refuse []string
}

func newEnv(t *testing.T, addrs map[string][]string, inside ...string) *env {
	t.Helper()
	e := &env{resolver: &fakeResolver{addrs: addrs}}
	e.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.got = append(e.got, r.Clone(context.Background()))
		e.mu.Unlock()
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "https://elsewhere.example.net/", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "hello from "+r.Host)
	}))
	t.Cleanup(e.srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(e.srv.Certificate())
	domains, err := upstream.ParseDomains(inside)
	if err != nil {
		t.Fatal(err)
	}
	e.sender = upstream.New(upstream.Config{
		Inside:     domains,
		Surrogates: upstream.NewSurrogates([]string{surrogate}),
		Resolver:   e.resolver,
		RootCAs:    roots,
		DialAddr: func(ctx context.Context, network, addr string) (net.Conn, error) {
			e.mu.Lock()
			e.dialed = append(e.dialed, addr)
			refused := slices.Contains(e.refuse, addr)
			e.mu.Unlock()
			if refused {
				return nil, errors.New("connection refused")
			}
			var d net.Dialer
			return d.DialContext(ctx, network, e.srv.Listener.Addr().String())
		},
	})
	return e
}

func (e *env) dials() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.dialed)
}

func (e *env) requests() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.got)
}

func (e *env) get(t *testing.T, url string, header http.Header) (*http.Response, *upstream.Report, error) {
	t.Helper()
	ctx, rep := upstream.WithReport(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, vs := range header {
		req.Header[k] = vs
	}
	resp, err := e.sender.RoundTrip(req)
	if resp != nil {
		t.Cleanup(func() { _ = resp.Body.Close() })
	}
	return resp, rep, err
}

func reason(t *testing.T, err error) upstream.Reason {
	t.Helper()
	var ue *upstream.Error
	if !errors.As(err, &ue) {
		t.Fatalf("error %v is not an upstream.Error", err)
	}
	return ue.Reason
}

func TestARequestIsSentToTheNameLookedUpAgainAndItsAddressIsReported(t *testing.T) {
	e := newEnv(t, map[string][]string{"example.com": {"192.0.2.10"}})
	resp, rep, err := e.get(t, "https://example.com/path", nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "hello from example.com" {
		t.Errorf("response = %d %q", resp.StatusCode, body)
	}
	if got := e.dials(); !slices.Equal(got, []string{"192.0.2.10:443"}) {
		t.Errorf("dialed %v", got)
	}
	if rep.Address != netip.MustParseAddrPort("192.0.2.10:443") || rep.Inside || rep.InsidePublic {
		t.Errorf("report = %+v", rep)
	}
	if !slices.Equal(rep.Resolved, []netip.Addr{netip.MustParseAddr("192.0.2.10")}) {
		t.Errorf("resolved = %v", rep.Resolved)
	}
}

func TestTheAddressCheckedIsTheAddressConnectedTo(t *testing.T) {
	e := newEnv(t, map[string][]string{"example.com": {"10.0.0.1", "2001:db8::10", "192.0.2.10"}})
	if _, _, err := e.get(t, "https://example.com/", nil); err != nil {
		t.Fatal(err)
	}
	if e.resolver.lookups != 1 {
		t.Errorf("the name was looked up %d times, want once", e.resolver.lookups)
	}
	if got := e.dials(); !slices.Equal(got, []string{"[2001:db8::10]:443"}) {
		t.Errorf("dialed %v, want the first public address only", got)
	}
}

func TestTheNextCheckedAddressIsTriedWhenOneCannotBeReached(t *testing.T) {
	e := newEnv(t, map[string][]string{"example.com": {"192.0.2.10", "192.0.2.11"}})
	e.refuse = []string{"192.0.2.10:443"}
	_, rep, err := e.get(t, "https://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Address != netip.MustParseAddrPort("192.0.2.11:443") {
		t.Errorf("report = %+v", rep)
	}
}

func TestARedirectIsHandedBackNotFollowed(t *testing.T) {
	e := newEnv(t, map[string][]string{"example.com": {"192.0.2.10"}})
	resp, _, err := e.get(t, "https://example.com/redirect", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "https://elsewhere.example.net/" {
		t.Errorf("response = %d %v", resp.StatusCode, resp.Header)
	}
	if e.requests() != 1 {
		t.Errorf("the upstream got %d requests", e.requests())
	}
}

func TestNothingIsAddedToTheRequest(t *testing.T) {
	e := newEnv(t, map[string][]string{"example.com": {"192.0.2.10"}})
	if _, _, err := e.get(t, "https://example.com/", nil); err != nil {
		t.Fatal(err)
	}
	r := e.got[0]
	for _, h := range []string{"Accept-Encoding", "User-Agent", "X-Forwarded-For", "Via"} {
		if v, ok := r.Header[h]; ok && v[0] != "" {
			t.Errorf("%s: %q was added", h, v)
		}
	}
	if r.Proto != "HTTP/1.1" {
		t.Errorf("sent as %s", r.Proto)
	}
}

func TestTheUpstreamCertificateIsCheckedForTheName(t *testing.T) {
	// The test server's certificate is for example.com.
	e := newEnv(t, map[string][]string{"other.example.net": {"192.0.2.10"}})
	_, _, err := e.get(t, "https://other.example.net/", nil)
	if got := reason(t, err); got != upstream.ReasonCertificate {
		t.Errorf("reason = %s, want %s", got, upstream.ReasonCertificate)
	}
	if e.requests() != 0 {
		t.Error("the request reached the upstream")
	}
}

func TestTheSystemRootsAreUsedWhenNoneAreGiven(t *testing.T) {
	e := newEnv(t, map[string][]string{"example.com": {"192.0.2.10"}})
	s := upstream.New(upstream.Config{
		Resolver: e.resolver,
		DialAddr: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, e.srv.Listener.Addr().String())
		},
	})
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	_, err := s.RoundTrip(req)
	if got := reason(t, err); got != upstream.ReasonCertificate {
		t.Errorf("reason = %s, want %s: the test server's own CA is not a system root", got, upstream.ReasonCertificate)
	}
}

func TestLoopbackAndLinkLocalAddressesAreNeverConnectedTo(t *testing.T) {
	for _, a := range []string{"127.0.0.1", "127.1.2.3", "::1", "169.254.169.254", "fe80::1", "::ffff:127.0.0.1", "::ffff:169.254.169.254", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "255.255.255.255"} {
		t.Run(a, func(t *testing.T) {
			for _, name := range []string{"example.com", "api.inside.example"} {
				e := newEnv(t, map[string][]string{name: {a}}, "inside.example")
				_, rep, err := e.get(t, "https://"+name+"/", nil)
				if got := reason(t, err); got != upstream.ReasonAddressLocal {
					t.Errorf("%s: reason = %s, want %s", name, got, upstream.ReasonAddressLocal)
				}
				var ue *upstream.Error
				errors.As(err, &ue)
				if !slices.Equal(ue.Resolved, []netip.Addr{netip.MustParseAddr(a)}) || !slices.Equal(rep.Resolved, ue.Resolved) {
					t.Errorf("%s: resolved = %v, report %v", name, ue.Resolved, rep.Resolved)
				}
				if len(e.dials()) != 0 {
					t.Errorf("%s: dialed %v", name, e.dials())
				}
			}
		})
	}
}

func TestAnOutsideNameIsNotConnectedToAPrivateAddress(t *testing.T) {
	for _, a := range []string{"10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "100.64.0.1", "fd00::1", "::ffff:10.0.0.1"} {
		t.Run(a, func(t *testing.T) {
			e := newEnv(t, map[string][]string{"example.com": {a}}, "inside.example")
			_, _, err := e.get(t, "https://example.com/", nil)
			if got := reason(t, err); got != upstream.ReasonAddressPrivate {
				t.Errorf("reason = %s, want %s", got, upstream.ReasonAddressPrivate)
			}
			if len(e.dials()) != 0 {
				t.Errorf("dialed %v", e.dials())
			}
		})
	}
}

func TestAnInsideNameIsConnectedToAPrivateAddress(t *testing.T) {
	for _, name := range []string{"inside.example", "api.inside.example", "API.Inside.Example."} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, map[string][]string{routesName(name): {"10.1.2.3"}}, "Inside.Example.")
			// The certificate is for example.com: only the connection is
			// looked at here.
			c, err := e.sender.Dial(context.Background(), name, 443)
			if err != nil {
				t.Fatal(err)
			}
			_ = c.Close()
			if c.Report.Address != netip.MustParseAddrPort("10.1.2.3:443") || !c.Report.Inside || c.Report.InsidePublic {
				t.Errorf("report = %+v", c.Report)
			}
		})
	}
}

func routesName(n string) string { return strings.ToLower(strings.TrimSuffix(n, ".")) }

func TestAnInsideNameThatPointsToAPublicAddressIsConnectedAndTold(t *testing.T) {
	e := newEnv(t, map[string][]string{"api.inside.example": {"192.0.2.10"}}, "inside.example")
	c, err := e.sender.Dial(context.Background(), "api.inside.example", 443)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if !c.Report.Inside || !c.Report.InsidePublic {
		t.Errorf("report = %+v", c.Report)
	}
}

func TestANameUnderNoInsideDomainIsOutside(t *testing.T) {
	// notinside.example ends with inside.example but is not under it.
	e := newEnv(t, map[string][]string{"notinside.example": {"10.0.0.1"}}, "inside.example")
	_, err := e.sender.Dial(context.Background(), "notinside.example", 443)
	if got := reason(t, err); got != upstream.ReasonAddressPrivate {
		t.Errorf("reason = %s", got)
	}
}

func TestOnlyPort443IsSentTo(t *testing.T) {
	e := newEnv(t, map[string][]string{"example.com": {"192.0.2.10"}})
	_, _, err := e.get(t, "https://example.com:8443/", nil)
	if got := reason(t, err); got != upstream.ReasonPort {
		t.Errorf("reason = %s, want %s", got, upstream.ReasonPort)
	}
	if _, err := e.sender.Dial(context.Background(), "example.com", 80); reason(t, err) != upstream.ReasonPort {
		t.Errorf("Dial to 80: %v", err)
	}
	if _, _, err := e.get(t, "https://example.com:443/", nil); err != nil {
		t.Errorf("an explicit 443: %v", err)
	}
}

func TestOnlyHTTPSIsSent(t *testing.T) {
	e := newEnv(t, map[string][]string{"example.com": {"192.0.2.10"}})
	_, _, err := e.get(t, "http://example.com/", nil)
	if got := reason(t, err); got != upstream.ReasonNotHTTPS {
		t.Errorf("reason = %s, want %s", got, upstream.ReasonNotHTTPS)
	}
	if len(e.dials()) != 0 {
		t.Errorf("dialed %v", e.dials())
	}
}

func TestARequestCarryingASurrogateIsRefusedUnsent(t *testing.T) {
	cases := map[string]struct {
		url    string
		header http.Header
	}{
		"in a header":            {url: "https://example.com/", header: http.Header{"Authorization": {"Bearer " + surrogate}}},
		"in part of a header":    {url: "https://example.com/", header: http.Header{"X-Note": {"a" + surrogate + "b"}}},
		"in the query":           {url: "https://example.com/?token=" + surrogate},
		"in the query, escaped":  {url: "https://example.com/?t=%73" + surrogate[1:]},
		"in the query, its name": {url: "https://example.com/?" + surrogate + "=1"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, map[string][]string{"example.com": {"192.0.2.10"}})
			_, _, err := e.get(t, c.url, c.header)
			if got := reason(t, err); got != upstream.ReasonSurrogate {
				t.Errorf("reason = %s, want %s", got, upstream.ReasonSurrogate)
			}
			if strings.Contains(err.Error(), surrogate) {
				t.Errorf("the error %q holds the surrogate", err)
			}
			if len(e.dials()) != 0 || e.requests() != 0 {
				t.Errorf("dialed %v, sent %d", e.dials(), e.requests())
			}
		})
	}
}

func TestANameThatCannotBeLookedUpIsUnreachable(t *testing.T) {
	e := newEnv(t, nil)
	_, _, err := e.get(t, "https://missing.example.com/", nil)
	if got := reason(t, err); got != upstream.ReasonUnreachable {
		t.Errorf("reason = %s, want %s", got, upstream.ReasonUnreachable)
	}
}

func TestNoCheckedAddressAnsweringIsUnreachableWithTheAddresses(t *testing.T) {
	e := newEnv(t, map[string][]string{"example.com": {"192.0.2.10"}})
	e.refuse = []string{"192.0.2.10:443"}
	_, _, err := e.get(t, "https://example.com/", nil)
	if got := reason(t, err); got != upstream.ReasonUnreachable {
		t.Errorf("reason = %s, want %s", got, upstream.ReasonUnreachable)
	}
	var ue *upstream.Error
	errors.As(err, &ue)
	if !slices.Equal(ue.Resolved, []netip.Addr{netip.MustParseAddr("192.0.2.10")}) {
		t.Errorf("resolved = %v", ue.Resolved)
	}
}

func TestAPassthroughDialReportsWhereItConnected(t *testing.T) {
	e := newEnv(t, map[string][]string{"example.com": {"2001:db8::10"}})
	c, err := e.sender.Dial(context.Background(), "example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if c.Report.Address != netip.MustParseAddrPort("[2001:db8::10]:443") {
		t.Errorf("report = %+v", c.Report)
	}
	// It is a plain TCP connection: the caller's TLS goes over it.
	if _, err := c.Write([]byte{0x16, 0x03, 0x01}); err != nil {
		t.Errorf("write: %v", err)
	}
}

func TestErrorsAreToldAsRefusalsOrFailures(t *testing.T) {
	for _, r := range []upstream.Reason{upstream.ReasonAddressLocal, upstream.ReasonAddressPrivate, upstream.ReasonSurrogate, upstream.ReasonPort, upstream.ReasonNotHTTPS} {
		if !(&upstream.Error{Reason: r}).Refused() {
			t.Errorf("%s is not a refusal", r)
		}
	}
	for _, r := range []upstream.Reason{upstream.ReasonUnreachable, upstream.ReasonCertificate, upstream.ReasonFailed} {
		if (&upstream.Error{Reason: r}).Refused() {
			t.Errorf("%s is a refusal", r)
		}
	}
}

// Other forms carry an IPv4 address inside an IPv6 one: 6to4
// (2002::/16, RFC 3056) and the old IPv4-compatible form (::/96). They are
// taken as the IPv4 address they carry. The local-use NAT64 prefix
// (64:ff9b:1::/48, RFC 8215) is the site's own translator, and private.
// The discard prefix (100::/64) reaches no one.
func TestIPv4CarriedInOtherIPv6FormsIsTakenAsTheIPv4Address(t *testing.T) {
	for _, tc := range []struct {
		addr string
		want upstream.Reason
	}{
		{"2002:7f00:1::1", upstream.ReasonAddressLocal},
		{"2002:a9fe:a9fe::1", upstream.ReasonAddressLocal},
		{"::127.0.0.1", upstream.ReasonAddressLocal},
		{"::169.254.169.254", upstream.ReasonAddressLocal},
		{"100::1", upstream.ReasonAddressLocal},
		{"2002:a01:203::1", upstream.ReasonAddressPrivate},
		{"2002:c0a8:101::1", upstream.ReasonAddressPrivate},
		{"::10.0.0.1", upstream.ReasonAddressPrivate},
		{"64:ff9b:1::a01:203", upstream.ReasonAddressPrivate},
	} {
		t.Run(tc.addr, func(t *testing.T) {
			e := newEnv(t, map[string][]string{"example.com": {tc.addr}}, "inside.example")
			_, _, err := e.get(t, "https://example.com/", nil)
			if got := reason(t, err); got != tc.want {
				t.Errorf("reason = %s, want %s", got, tc.want)
			}
			if len(e.dials()) != 0 {
				t.Errorf("dialed %v", e.dials())
			}
		})
	}
}

func TestA6to4AddressCarryingAPublicIPv4AddressIsPublic(t *testing.T) {
	// 2002:c000:20a:: carries 192.0.2.10.
	e := newEnv(t, map[string][]string{"example.com": {"2002:c000:20a::1"}})
	resp, rep, err := e.get(t, "https://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if rep.Address != netip.MustParseAddrPort("[2002:c000:20a::1]:443") {
		t.Errorf("address = %s", rep.Address)
	}
}
