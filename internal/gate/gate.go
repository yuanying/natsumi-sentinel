// Package gate is the gate's transparent listener: it takes the connections
// iptables redirects to it from one source (the workspace, at first), finds
// where each was going, and opens, passes through or denies it by the
// routing table (docs/adr/0002). Every connection and every request read is
// recorded, and nothing goes out that could not be recorded first
// (docs/adr/0006).
//
// The gate does not send requests on open destinations to their upstream
// itself. It hands each one, with the name and port it decided on in the
// URL and the surrogate still on it, to Config.Upstream, which is authd's
// side of the socket (docs/adr/0003).
package gate

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/certs"
	"github.com/yuanying/natsumi-sentinel/internal/decide"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

// Recorder is the audit log as the gate uses it.
type Recorder interface {
	Write(ctx context.Context, rec *audit.Record) error
	Begin(ctx context.Context, rec *audit.Record) error
	Finish(ctx context.Context, rec *audit.Record) error
}

// Config is what a Gate needs.
type Config struct {
	// Source names the listener in every record: where the connections
	// it takes were redirected from.
	Source string
	// Routes returns the routing table in use. It is asked once per
	// connection, so a table read again applies to new connections.
	Routes   func() *routes.Table
	Decider  decide.Decider
	Minter   *certs.Minter
	Log      Recorder
	Upstream http.RoundTripper
	// OriginalDst finds where a connection was going.
	OriginalDst func(net.Conn) (netip.AddrPort, error)
	// Dial connects a passthrough. Defaults to a net.Dialer.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// FirstByteTimeout is how long a connection may stay silent before
	// the gate gives up on finding out what it is. Defaults to 10s.
	FirstByteTimeout time.Duration
	// Agent serves the workspace's door to the gate (docs/approvals-api.md)
	// on plain HTTP to AgentAddr, the gate's own address and port 80. Nil
	// leaves the door shut.
	Agent     http.Handler
	AgentAddr netip.AddrPort
	// StatusURL is where the workspace reads its approvals, told in the
	// answer to an asked request. Empty leaves it out.
	StatusURL string
	// Logger is for what goes wrong in the gate itself, not for records.
	Logger *slog.Logger
	Now    func() time.Time
}

// Gate serves one listener.
type Gate struct {
	cfg  Config
	http *http.Server
	tlsc *connQueue
	// agent serves the workspace's door, fed by agentc.
	agent  *http.Server
	agentc *connQueue

	mu        sync.Mutex
	listeners []net.Listener
	closed    bool
}

// New makes a Gate. Serve starts it.
func New(cfg Config) *Gate {
	if cfg.Dial == nil {
		d := &net.Dialer{Timeout: 10 * time.Second}
		cfg.Dial = d.DialContext
	}
	if cfg.FirstByteTimeout == 0 {
		cfg.FirstByteTimeout = 10 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	g := &Gate{cfg: cfg, tlsc: newConnQueue()}
	g.http = &http.Server{
		Handler:           http.HandlerFunc(g.serveHTTP),
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       5 * time.Minute,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if oc, ok := c.(*openConn); ok {
				return context.WithValue(ctx, connKey{}, oc)
			}
			return ctx
		},
		ConnState: g.connState,
		ErrorLog:  slog.NewLogLogger(cfg.Logger.Handler(), slog.LevelWarn),
	}
	go func() { _ = g.http.Serve(g.tlsc) }()
	if cfg.Agent != nil {
		g.agentc = newConnQueue()
		g.agent = &http.Server{
			Handler:           cfg.Agent,
			ReadHeaderTimeout: 30 * time.Second,
			IdleTimeout:       time.Minute,
			ErrorLog:          slog.NewLogLogger(cfg.Logger.Handler(), slog.LevelWarn),
		}
		go func() { _ = g.agent.Serve(g.agentc) }()
	}
	return g
}

// Serve takes connections from ln until it is closed.
func (g *Gate) Serve(ln net.Listener) error {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return net.ErrClosed
	}
	g.listeners = append(g.listeners, ln)
	g.mu.Unlock()
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go g.handle(c)
	}
}

// Close stops taking connections and closes the ones in flight.
func (g *Gate) Close() error {
	g.mu.Lock()
	g.closed = true
	lns := g.listeners
	g.mu.Unlock()
	for _, ln := range lns {
		_ = ln.Close()
	}
	if g.agent != nil {
		_ = g.agent.Close()
	}
	return g.http.Close()
}

// base is the start of every record made for a connection.
func (g *Gate) base(kind audit.Kind, dst netip.AddrPort) *audit.Record {
	rec := &audit.Record{Time: g.cfg.Now(), Source: g.cfg.Source, Kind: kind}
	if dst.IsValid() {
		rec.Address = dst.String()
	}
	return rec
}

// refuseConn records a connection refused before any request was read.
func (g *Gate) refuseConn(rec *audit.Record, reason string) {
	rec.Verdict = audit.Deny
	rec.Reason = reason
	if rec.Treatment == "" {
		rec.Treatment = string(routes.Closed)
	}
	if err := g.cfg.Log.Write(context.Background(), rec); err != nil {
		g.cfg.Logger.Error("a refused connection could not be recorded", "error", err)
	}
}

func (g *Gate) handle(c net.Conn) {
	dst, err := g.cfg.OriginalDst(c)
	if err != nil {
		rec := g.base(audit.KindConnection, netip.AddrPort{})
		rec.Error = err.Error()
		g.refuseConn(rec, "the connection's original destination is not known")
		_ = c.Close()
		return
	}
	if g.agent != nil && netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port()) == g.cfg.AgentAddr {
		if err := g.agentc.push(c); err != nil {
			_ = c.Close()
		}
		return
	}
	table := g.cfg.Routes()
	if table.Passthrough(dst) {
		g.passthrough(c, dst)
		return
	}

	pc := &peekConn{Conn: c, r: bufio.NewReader(c)}
	_ = c.SetReadDeadline(time.Now().Add(g.cfg.FirstByteTimeout))
	first, err := pc.r.Peek(1)
	if err != nil {
		rec := g.base(audit.KindConnection, dst)
		rec.Error = err.Error()
		g.refuseConn(rec, "nothing was sent to a destination that is not passed through")
		_ = c.Close()
		return
	}
	// 0x16 is a TLS handshake record.
	if first[0] == 0x16 {
		g.terminateTLS(pc, dst, table)
		return
	}
	g.plain(pc, dst)
}

// plain answers a connection that is not TLS: plain HTTP gets the gate's
// refusal, anything else is cut off.
func (g *Gate) plain(pc *peekConn, dst netip.AddrPort) {
	defer func() { _ = pc.Close() }()
	rec := g.base(audit.KindConnection, dst)
	req, err := http.ReadRequest(pc.r)
	if err != nil {
		g.refuseConn(rec, "neither TLS nor HTTP to a destination that is not passed through")
		return
	}
	rec.Name = routes.Normalize(hostOnly(req.Host))
	rec.Method = req.Method
	rec.Path = req.URL.Path
	rec.Query = req.URL.RawQuery
	reason := "plain HTTP is not opened; the gate opens HTTPS only"
	g.refuseConn(rec, reason)
	_ = pc.SetWriteDeadline(time.Now().Add(10 * time.Second))
	resp := refusal(req, http.StatusForbidden, MarkDeny, reason)
	_ = resp.Write(pc)
}

var (
	errNoSNI     = errors.New("no SNI")
	errNotOpened = errors.New("not opened")
)

// terminateTLS terminates TLS for an open destination with a certificate
// made for its name, and hands the connection to the HTTP server.
func (g *Gate) terminateTLS(pc *peekConn, dst netip.AddrPort, table *routes.Table) {
	var (
		sni  string
		dest routes.Destination
	)
	conf := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni = routes.Normalize(hello.ServerName)
			if sni == "" {
				return nil, errNoSNI
			}
			d, ok := table.Lookup(sni, dst.Port())
			if !ok || d.Treatment != routes.Open {
				return nil, errNotOpened
			}
			dest = d
			cert, err := g.cfg.Minter.Certificate(sni)
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{*cert},
				// HTTP/1.1 only, for now.
				NextProtos: []string{"http/1.1"},
			}, nil
		},
	}
	tc := tls.Server(pc, conf)
	_ = pc.SetDeadline(time.Now().Add(g.cfg.FirstByteTimeout))
	err := tc.Handshake()
	if err != nil {
		rec := g.base(audit.KindConnection, dst)
		rec.Name = sni
		switch {
		case errors.Is(err, errNoSNI):
			g.refuseConn(rec, "TLS without SNI; the gate decides by name")
		case errors.Is(err, errNotOpened):
			if d, ok := table.Lookup(sni, dst.Port()); ok {
				rec.Treatment = string(d.Treatment)
				g.refuseConn(rec, "the routing table denies this destination")
			} else {
				g.refuseConn(rec, "not in the routing table on this port")
			}
		default:
			rec.Treatment = string(routes.Open)
			rec.Error = err.Error()
			g.refuseConn(rec, "the TLS handshake failed")
		}
		_ = tc.Close()
		return
	}
	_ = pc.SetDeadline(time.Time{})
	if err := g.tlsc.push(&openConn{Conn: tc, sni: sni, dst: dst, dest: dest}); err != nil {
		_ = tc.Close()
	}
}

// openConn is a TLS connection to an open destination, carrying what was
// learned before its first request.
type openConn struct {
	net.Conn
	sni  string
	dst  netip.AddrPort
	dest routes.Destination

	mu     sync.Mutex
	served bool
	// sent is whether anything came on the connection after the
	// handshake.
	sent bool
	at   time.Time
}

// Read notes that something came, so that a connection closed before
// anything did is told apart from one whose bytes were not a request.
func (oc *openConn) Read(b []byte) (int, error) {
	n, err := oc.Conn.Read(b)
	if n > 0 {
		oc.mu.Lock()
		oc.sent = true
		oc.mu.Unlock()
	}
	return n, err
}

type connKey struct{}

// connState records a TLS connection that closed without a single request
// reaching the gate. When nothing came at all, the tool opened it and did
// not use it (HTTP clients dial ahead and keep what they do not need idle):
// nothing was refused, and it is recorded as allowed. When something came,
// the HTTP server refused it (a request without Host, or one it could not
// read).
func (g *Gate) connState(c net.Conn, state http.ConnState) {
	oc, ok := c.(*openConn)
	if !ok {
		return
	}
	switch state {
	case http.StateNew:
		oc.mu.Lock()
		oc.at = g.cfg.Now()
		oc.mu.Unlock()
	case http.StateClosed:
		oc.mu.Lock()
		served, sent := oc.served, oc.sent
		oc.mu.Unlock()
		if served {
			return
		}
		rec := g.base(audit.KindConnection, oc.dst)
		rec.Name = oc.sni
		rec.Treatment = string(routes.Open)
		if !sent {
			rec.Verdict = audit.Allow
			rec.Reason = audit.ReasonConnectionUnused
			if err := g.cfg.Log.Write(context.Background(), rec); err != nil {
				g.cfg.Logger.Error("an unused connection could not be recorded", "error", err)
			}
			return
		}
		g.refuseConn(rec, "no request was read on the connection (no Host, or not HTTP/1.1)")
	}
}

// peekConn is a connection whose first bytes have been read into r.
type peekConn struct {
	net.Conn
	r *bufio.Reader
}

func (p *peekConn) Read(b []byte) (int, error) { return p.r.Read(b) }

// connQueue is a net.Listener fed by the gate, so that the HTTP server
// serves connections the gate has already terminated TLS on.
type connQueue struct {
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

func newConnQueue() *connQueue {
	return &connQueue{ch: make(chan net.Conn), done: make(chan struct{})}
}

func (q *connQueue) push(c net.Conn) error {
	select {
	case q.ch <- c:
		return nil
	case <-q.done:
		return net.ErrClosed
	}
}

func (q *connQueue) Accept() (net.Conn, error) {
	select {
	case c := <-q.ch:
		return c, nil
	case <-q.done:
		return nil, net.ErrClosed
	}
}

func (q *connQueue) Close() error {
	q.once.Do(func() { close(q.done) })
	return nil
}

func (q *connQueue) Addr() net.Addr { return queueAddr{} }

type queueAddr struct{}

func (queueAddr) Network() string { return "gate" }
func (queueAddr) String() string  { return "gate" }

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}
