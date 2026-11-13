// Package dnsgate is the gate's name resolution: the workspace's DNS is
// redirected here, over UDP and TCP (docs/adr/0002). Names that are open in
// the routing table are answered with their real addresses, the gate's own
// fixed names with the gate's address, and every other name with NXDOMAIN.
// Every query is recorded (docs/adr/0006).
//
// A is answered always, and AAAA only for a source whose IPv6 is redirected
// to the gate too (Config.IPv6): a real IPv6 address the workspace would
// connect to straight out must not be handed out. Without it, an AAAA query
// for a name that is answered gets NOERROR with no records, and the
// workspace reaches everything over IPv4.
package dnsgate

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/decide"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

// Resolver looks names up in the real DNS. *net.Resolver is one.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Recorder is the audit log as name resolution uses it.
type Recorder interface {
	Write(ctx context.Context, rec *audit.Record) error
}

// Config is what a Server needs.
type Config struct {
	Source string
	Routes func() *routes.Table
	// Names decides which names are answered (docs/adr/0008: one place
	// decides for names, connections and requests). Defaults to a
	// decide.Table without a ledger.
	Names    decide.NameDecider
	Resolver Resolver
	// Fixed are the gate's own names, answered with the address given.
	Fixed  map[string]netip.Addr
	Log    Recorder
	Logger *slog.Logger
	Now    func() time.Time
	// TTL is the TTL of the answers. Defaults to 30 seconds, so that a
	// table read again is felt soon.
	TTL uint32
	// Timeout bounds one lookup. Defaults to 5 seconds.
	Timeout time.Duration
	// SearchSuffixes are the search list of the workspace's resolver (the
	// cluster's, such as svc.cluster.local). A refused query for a name in
	// the table with one of them added is told by its own reason, which is
	// not a notice's pair.
	SearchSuffixes []string
	// IPv6 is set when the source's IPv6 is redirected to the gate as its
	// IPv4 is. Only then are open names answered in AAAA, with their real
	// IPv6 addresses, and a name with no IPv4 address is told to be there.
	IPv6 bool
}

// Server answers queries.
type Server struct {
	cfg   Config
	fixed map[string]netip.Addr
}

// New makes a Server.
func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.TTL == 0 {
		cfg.TTL = 30
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.Names == nil {
		cfg.Names = decide.Table{}
	}
	fixed := map[string]netip.Addr{}
	for name, addr := range cfg.Fixed {
		fixed[routes.Normalize(name)] = addr
	}
	return &Server{cfg: cfg, fixed: fixed}
}

// ServeUDP answers queries on pc until it is closed.
func (s *Server) ServeUDP(pc net.PacketConn) error {
	buf := make([]byte, 65535)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		q := append([]byte(nil), buf[:n]...)
		go func() {
			resp := s.Answer(context.Background(), q)
			if resp == nil {
				return
			}
			if len(resp) > 512 {
				resp = truncate(resp)
			}
			_, _ = pc.WriteTo(resp, addr)
		}()
	}
}

// ServeTCP answers queries on connections from ln until it is closed.
func (s *Server) ServeTCP(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.serveConn(c)
	}
}

func (s *Server) serveConn(c net.Conn) {
	defer func() { _ = c.Close() }()
	for {
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		q := make([]byte, binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(c, q); err != nil {
			return
		}
		resp := s.Answer(context.Background(), q)
		if resp == nil {
			return
		}
		if _, err := c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(resp))), resp...)); err != nil {
			return
		}
	}
}

// Answer answers one query message. It returns nil for a message that is
// not worth an answer (too short to have a header).
func (s *Server) Answer(ctx context.Context, msg []byte) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return nil
	}
	questions, err := p.AllQuestions()
	if err != nil || len(questions) != 1 || h.Response {
		return reply(h, nil, dnsmessage.RCodeFormatError, nil, 0)
	}
	q := questions[0]
	if h.OpCode != 0 {
		return reply(h, &q, dnsmessage.RCodeNotImplemented, nil, 0)
	}

	name := routes.Normalize(q.Name.String())
	rec := &audit.Record{
		Time:    s.cfg.Now(),
		Source:  s.cfg.Source,
		Kind:    audit.KindDNS,
		Name:    name,
		DNSType: strings.TrimPrefix(q.Type.String(), "Type"),
	}
	rcode, addrs := s.resolve(ctx, rec, name, q.Type)
	rec.DNSRcode = rcodeName(rcode)
	rec.DNSAnswer = make([]string, 0, len(addrs))
	for _, a := range addrs {
		rec.DNSAnswer = append(rec.DNSAnswer, a.String())
	}
	// An answer that could not be recorded is not given (docs/adr/0006).
	if err := s.cfg.Log.Write(ctx, rec); err != nil {
		s.cfg.Logger.Error("a name resolution query could not be recorded, so it was not answered", "name", name, "error", err)
		return reply(h, &q, dnsmessage.RCodeServerFailure, nil, 0)
	}
	return reply(h, &q, rcode, addrs, s.cfg.TTL)
}

// resolve decides on a query and fills in the record's verdict.
func (s *Server) resolve(ctx context.Context, rec *audit.Record, name string, typ dnsmessage.Type) (dnsmessage.RCode, []netip.Addr) {
	if addr, ok := s.fixed[name]; ok {
		rec.Verdict, rec.Reason = audit.Allow, "the gate's own name"
		if typ == dnsmessage.TypeA && addr.Is4() {
			return dnsmessage.RCodeSuccess, []netip.Addr{addr}
		}
		return dnsmessage.RCodeSuccess, nil
	}
	ans := s.cfg.Names.DecideName(ctx, decide.NameQuery{
		Source:         s.cfg.Source,
		Routes:         s.cfg.Routes(),
		Name:           name,
		SearchSuffixes: s.cfg.SearchSuffixes,
	})
	rec.Treatment = string(ans.Treatment)
	rec.Verdict, rec.Reason = ans.Verdict, ans.Reason
	if ans.Verdict != audit.Allow {
		return dnsmessage.RCodeNameError, nil
	}
	var network, other string
	switch {
	case typ == dnsmessage.TypeA:
		network, other = "ip4", "ip6"
	case typ == dnsmessage.TypeAAAA && s.cfg.IPv6:
		network, other = "ip6", "ip4"
	default:
		return dnsmessage.RCodeSuccess, nil
	}
	addrs, rcode := s.lookup(ctx, rec, name, network)
	if rcode != dnsmessage.RCodeNameError || !s.cfg.IPv6 {
		return rcode, addrs
	}
	// The name may be there with addresses of the other family only: then
	// it is NOERROR with no records, so that the resolver goes on to ask
	// for the other.
	found, rcode := s.lookup(ctx, rec, name, other)
	switch {
	case rcode == dnsmessage.RCodeSuccess && len(found) > 0:
		return dnsmessage.RCodeSuccess, nil
	case rcode == dnsmessage.RCodeServerFailure:
		return rcode, nil
	}
	return dnsmessage.RCodeNameError, nil
}

// lookup asks the real DNS for name's addresses of one family ("ip4" or
// "ip6"). A name not found is NXDOMAIN; any other failure is SERVFAIL, with
// the error in the record.
func (s *Server) lookup(ctx context.Context, rec *audit.Record, name, network string) ([]netip.Addr, dnsmessage.RCode) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	addrs, err := s.cfg.Resolver.LookupNetIP(ctx, network, name)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil, dnsmessage.RCodeNameError
		}
		rec.Error = err.Error()
		return nil, dnsmessage.RCodeServerFailure
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if network == "ip4" {
			if a = a.Unmap(); a.Is4() {
				out = append(out, a)
			}
		} else if a.Is6() && !a.Is4In6() {
			out = append(out, a)
		}
	}
	return out, dnsmessage.RCodeSuccess
}

func reply(q dnsmessage.Header, question *dnsmessage.Question, rcode dnsmessage.RCode, addrs []netip.Addr, ttl uint32) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 q.ID,
		Response:           true,
		OpCode:             q.OpCode,
		RecursionDesired:   q.RecursionDesired,
		RecursionAvailable: true,
		RCode:              rcode,
	})
	b.EnableCompression()
	if question != nil {
		if err := b.StartQuestions(); err != nil {
			return nil
		}
		if err := b.Question(*question); err != nil {
			return nil
		}
		if err := b.StartAnswers(); err != nil {
			return nil
		}
		for _, a := range addrs {
			if a.Is4() {
				rh := dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: ttl}
				if err := b.AResource(rh, dnsmessage.AResource{A: a.As4()}); err != nil {
					return nil
				}
				continue
			}
			rh := dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: ttl}
			if err := b.AAAAResource(rh, dnsmessage.AAAAResource{AAAA: a.As16()}); err != nil {
				return nil
			}
		}
	}
	msg, err := b.Finish()
	if err != nil {
		return nil
	}
	return msg
}

// truncate drops the answers and sets TC, so that the client asks again
// over TCP.
func truncate(resp []byte) []byte {
	var m dnsmessage.Message
	if err := m.Unpack(resp); err != nil {
		return nil
	}
	m.Truncated = true
	m.Answers = nil
	out, err := m.Pack()
	if err != nil {
		return nil
	}
	return out
}

func rcodeName(r dnsmessage.RCode) string {
	switch r {
	case dnsmessage.RCodeSuccess:
		return "NOERROR"
	case dnsmessage.RCodeFormatError:
		return "FORMERR"
	case dnsmessage.RCodeServerFailure:
		return "SERVFAIL"
	case dnsmessage.RCodeNameError:
		return "NXDOMAIN"
	case dnsmessage.RCodeNotImplemented:
		return "NOTIMP"
	case dnsmessage.RCodeRefused:
		return "REFUSED"
	}
	return r.String()
}
