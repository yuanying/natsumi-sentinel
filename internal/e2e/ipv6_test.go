package e2e_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/dnsgate"
)

// ipv6OnlyDNS is the real DNS of the test: example.com has an IPv6 address
// and no IPv4 one.
type ipv6OnlyDNS struct{}

var exampleIPv6 = netip.MustParseAddr("2001:db8::7")

func (ipv6OnlyDNS) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	if host == "example.com" && (network == "ip6" || network == "ip") {
		return []netip.Addr{exampleIPv6}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func ask(t *testing.T, s *dnsgate.Server, name string, typ dnsmessage.Type) dnsmessage.Message {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, RecursionDesired: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET})
	q, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(s.Answer(context.Background(), q)); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestANameWithOnlyAnIPv6AddressIsReachedThroughTheGateAndAuthdOverIPv6(t *testing.T) {
	up6, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback here: %v", err)
	}

	var (
		mu      sync.Mutex
		origDst netip.AddrPort
		dialed  []string
	)
	w := newWorldOpts(t, routesYAML, func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(rw, "from upstream")
	}, worldOptions{
		upstream: up6,
		// authd looks the name up again, as it does for real, and connects
		// to what it finds. 2001:db8::7 stands for the fake upstream on the
		// IPv6 loopback.
		authdDial: func(upstreamAddr string) func(ctx context.Context, network, addr string) (net.Conn, error) {
			return func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				addrs, err := ipv6OnlyDNS{}.LookupNetIP(ctx, "ip", host)
				if err != nil {
					return nil, err
				}
				mu.Lock()
				dialed = append(dialed, net.JoinHostPort(addrs[0].String(), port))
				mu.Unlock()
				if addrs[0] != exampleIPv6 {
					return nil, errors.New("not the fake upstream")
				}
				var d net.Dialer
				return d.DialContext(ctx, "tcp6", upstreamAddr)
			}
		},
		originalDst: func(net.Conn) (netip.AddrPort, error) {
			mu.Lock()
			defer mu.Unlock()
			return origDst, nil
		},
	})

	dns := dnsgate.New(dnsgate.Config{
		Source: "workspace", Routes: w.watcher.Current, Resolver: ipv6OnlyDNS{}, Log: w.log, IPv6: true,
	})
	// The workspace's resolver asks for both, and is told the name is
	// there with an IPv6 address only.
	if m := ask(t, dns, "example.com.", dnsmessage.TypeA); m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 0 {
		t.Fatalf("A = %v with %d records, want NOERROR and none", m.RCode, len(m.Answers))
	}
	m := ask(t, dns, "example.com.", dnsmessage.TypeAAAA)
	if m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 {
		t.Fatalf("AAAA = %v with %d records, want the real IPv6 address", m.RCode, len(m.Answers))
	}
	got := netip.AddrFrom16(m.Answers[0].Body.(*dnsmessage.AAAAResource).AAAA)
	if got != exampleIPv6 {
		t.Fatalf("AAAA = %v, want %v", got, exampleIPv6)
	}
	// It connects there, and ip6tables would send it to the gate.
	mu.Lock()
	origDst = netip.AddrPortFrom(got, 443)
	mu.Unlock()

	resp, body := w.do(http.MethodGet, "https://example.com/repos/o/r", "")
	if resp.StatusCode != http.StatusCreated || body != "from upstream" {
		t.Fatalf("response = %d %q", resp.StatusCode, body)
	}
	seen := w.upstreamSaw()
	if len(seen) != 1 || seen[0].Header.Get("Authorization") != "Bearer "+realKey {
		t.Fatalf("the upstream saw %d requests, want one with the real key", len(seen))
	}
	mu.Lock()
	if len(dialed) != 1 || dialed[0] != "["+exampleIPv6.String()+"]:"+strconv.Itoa(443) {
		t.Errorf("authd connected to %v, want the name's IPv6 address", dialed)
	}
	mu.Unlock()
	rec := w.lastRecord()
	if rec.Kind != audit.KindHTTP || rec.Name != "example.com" || rec.Address != "[2001:db8::7]:443" || rec.Verdict != audit.Allow {
		t.Errorf("record = %+v", rec)
	}
}
