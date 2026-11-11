package dnsgate_test

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/dnsgate"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

type memLog struct {
	mu      sync.Mutex
	records []audit.Record
	fail    bool
}

func (m *memLog) Write(_ context.Context, rec *audit.Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return errors.New("disk full")
	}
	m.records = append(m.records, *rec)
	return nil
}

func (m *memLog) last(t *testing.T) audit.Record {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.records) == 0 {
		t.Fatal("nothing was recorded")
	}
	return m.records[len(m.records)-1]
}

type fakeResolver map[string][]netip.Addr

func (f fakeResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	if network != "ip4" {
		return nil, errors.New("only ip4 is asked for")
	}
	addrs, ok := f[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return addrs, nil
}

const table = `
destinations:
  - name: api.example.com
    treatment: open
    default: allow
  - name: gone.example.com
    treatment: open
    default: allow
  - name: broken.example.com
    treatment: open
    default: allow
  - name: blocked.example.com
    treatment: deny
`

func newServer(t *testing.T) (*dnsgate.Server, *memLog) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "routes.yaml"), []byte(table), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := routes.NewWatcher(dir)
	if err != nil {
		t.Fatal(err)
	}
	log := &memLog{}
	res := fakeResolver{"api.example.com": {netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("198.51.100.8")}}
	s := dnsgate.New(dnsgate.Config{
		Source: "workspace",
		Routes: w.Current,
		Resolver: resolverFunc(func(ctx context.Context, network, host string) ([]netip.Addr, error) {
			if host == "broken.example.com" {
				return nil, errors.New("upstream DNS timed out")
			}
			return res.LookupNetIP(ctx, network, host)
		}),
		Fixed: map[string]netip.Addr{"sentinel.internal": netip.MustParseAddr("127.0.0.1")},
		Log:   log,
	})
	return s, log
}

type resolverFunc func(ctx context.Context, network, host string) ([]netip.Addr, error)

func (f resolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

func query(t *testing.T, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 4242, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func parse(t *testing.T, b []byte) dnsmessage.Message {
	t.Helper()
	var m dnsmessage.Message
	if err := m.Unpack(b); err != nil {
		t.Fatalf("the answer does not parse: %v", err)
	}
	return m
}

func aAnswers(m dnsmessage.Message) []netip.Addr {
	var out []netip.Addr
	for _, a := range m.Answers {
		if r, ok := a.Body.(*dnsmessage.AResource); ok {
			out = append(out, netip.AddrFrom4(r.A))
		}
	}
	return out
}

func TestAnOpenNameIsAnsweredWithItsRealAddresses(t *testing.T) {
	s, log := newServer(t)
	m := parse(t, s.Answer(context.Background(), query(t, "API.example.com.", dnsmessage.TypeA)))
	if m.ID != 4242 || !m.Response || m.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("header = %+v", m.Header)
	}
	got := aAnswers(m)
	if len(got) != 2 || got[0].String() != "198.51.100.7" || got[1].String() != "198.51.100.8" {
		t.Errorf("answers = %v", got)
	}
	if len(m.Questions) != 1 {
		t.Errorf("the question was not echoed")
	}
	rec := log.last(t)
	if rec.Kind != audit.KindDNS || rec.Name != "api.example.com" || rec.DNSType != "A" || rec.DNSRcode != "NOERROR" ||
		rec.Verdict != audit.Allow || len(rec.DNSAnswer) != 2 || rec.Source != "workspace" {
		t.Errorf("record = %+v", rec)
	}
}

func TestANameNotOpenedIsNXDOMAINAndRecordedAsDenied(t *testing.T) {
	for _, name := range []string{"unknown.example.com.", "blocked.example.com."} {
		t.Run(name, func(t *testing.T) {
			s, log := newServer(t)
			m := parse(t, s.Answer(context.Background(), query(t, name, dnsmessage.TypeA)))
			if m.RCode != dnsmessage.RCodeNameError || len(m.Answers) != 0 {
				t.Errorf("answer = %v with %d records, want NXDOMAIN and none", m.RCode, len(m.Answers))
			}
			rec := log.last(t)
			if rec.Verdict != audit.Deny || rec.DNSRcode != "NXDOMAIN" {
				t.Errorf("record = %+v", rec)
			}
		})
	}
}

func TestAnOpenNameHasNoIPv6Answer(t *testing.T) {
	s, _ := newServer(t)
	m := parse(t, s.Answer(context.Background(), query(t, "api.example.com.", dnsmessage.TypeAAAA)))
	if m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 0 {
		t.Errorf("answer = %v with %d records, want NOERROR and none", m.RCode, len(m.Answers))
	}
}

func TestTheGatesOwnNameIsAnswered(t *testing.T) {
	s, log := newServer(t)
	m := parse(t, s.Answer(context.Background(), query(t, "sentinel.internal.", dnsmessage.TypeA)))
	got := aAnswers(m)
	if m.RCode != dnsmessage.RCodeSuccess || len(got) != 1 || got[0].String() != "127.0.0.1" {
		t.Errorf("answer = %v %v", m.RCode, got)
	}
	if rec := log.last(t); rec.Verdict != audit.Allow {
		t.Errorf("record = %+v", rec)
	}
}

func TestAnOpenNameThatDoesNotExistUpstreamIsNXDOMAIN(t *testing.T) {
	s, _ := newServer(t)
	m := parse(t, s.Answer(context.Background(), query(t, "gone.example.com.", dnsmessage.TypeA)))
	if m.RCode != dnsmessage.RCodeNameError {
		t.Errorf("rcode = %v, want NXDOMAIN", m.RCode)
	}
}

func TestAResolverThatFailsIsSERVFAIL(t *testing.T) {
	s, log := newServer(t)
	m := parse(t, s.Answer(context.Background(), query(t, "broken.example.com.", dnsmessage.TypeA)))
	if m.RCode != dnsmessage.RCodeServerFailure {
		t.Errorf("rcode = %v, want SERVFAIL", m.RCode)
	}
	if rec := log.last(t); rec.Error == "" {
		t.Errorf("record = %+v, want the error", rec)
	}
}

func TestAQueryThatCannotBeRecordedIsNotAnswered(t *testing.T) {
	s, log := newServer(t)
	log.fail = true
	m := parse(t, s.Answer(context.Background(), query(t, "api.example.com.", dnsmessage.TypeA)))
	if m.RCode != dnsmessage.RCodeServerFailure || len(m.Answers) != 0 {
		t.Errorf("answer = %v with %d records, want SERVFAIL and none", m.RCode, len(m.Answers))
	}
}

func TestSomethingThatIsNotAQueryGetsNoAddress(t *testing.T) {
	s, _ := newServer(t)
	if got := s.Answer(context.Background(), []byte{1, 2, 3}); got != nil {
		t.Errorf("Answer = %v, want nothing for a message too short to answer", got)
	}
}

func TestQueriesAreAnsweredOverUDPAndTCP(t *testing.T) {
	s, _ := newServer(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.ServeUDP(pc) }()
	go func() { _ = s.ServeTCP(ln) }()
	t.Cleanup(func() { _ = pc.Close(); _ = ln.Close() })

	u, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = u.Close() }()
	_ = u.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := u.Write(query(t, "api.example.com.", dnsmessage.TypeA)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	n, err := u.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := aAnswers(parse(t, buf[:n])); len(got) != 2 {
		t.Errorf("over UDP: answers = %v", got)
	}

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	for range 2 { // two queries on one connection
		q := query(t, "api.example.com.", dnsmessage.TypeA)
		if _, err := c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...)); err != nil {
			t.Fatal(err)
		}
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			t.Fatal(err)
		}
		resp := make([]byte, binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(c, resp); err != nil {
			t.Fatal(err)
		}
		if got := aAnswers(parse(t, resp)); len(got) != 2 {
			t.Errorf("over TCP: answers = %v", got)
		}
	}
}

func TestANameTheTableDeniesAndANameNotInTheTableAreToldApartByTheReason(t *testing.T) {
	s, log := newServer(t)
	s.Answer(context.Background(), query(t, "blocked.example.com.", dnsmessage.TypeA))
	denied := log.last(t)
	s.Answer(context.Background(), query(t, "unknown.example.com.", dnsmessage.TypeA))
	unlisted := log.last(t)

	if denied.Reason != audit.ReasonDNSDenied {
		t.Errorf("the denied name's reason = %q, want %q", denied.Reason, audit.ReasonDNSDenied)
	}
	if unlisted.Reason != audit.ReasonDNSNotListed {
		t.Errorf("the unlisted name's reason = %q, want %q", unlisted.Reason, audit.ReasonDNSNotListed)
	}
	if denied.Reason == unlisted.Reason {
		t.Errorf("both reasons are %q", denied.Reason)
	}
	// What was said before stays at the head of both, so that what looks
	// for it still finds it.
	for _, r := range []string{denied.Reason, unlisted.Reason} {
		if !strings.HasPrefix(r, "not an open destination in the routing table") {
			t.Errorf("reason %q does not start as before", r)
		}
	}
	if denied.Treatment != "deny" || unlisted.Treatment != "deny" {
		t.Errorf("treatments = %q, %q, want deny for both", denied.Treatment, unlisted.Treatment)
	}
}
