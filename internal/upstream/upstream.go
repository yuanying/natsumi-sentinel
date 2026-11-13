// Package upstream is the part of the gate that sends upstream itself
// (docs/adr/0007 "上流へ送る部品が守ること", docs/adr/0008 "宛先の許しの通信
// は、関所が鍵を付けずに直に送る", docs/destination-grants.md "関所が直に
// 送る").
//
// A Sender looks the name the gate decided on up again, and connects to
// the addresses it found, never to the address the workspace connected to.
// Loopback and link-local addresses are never connected to; private ones
// only for a name under an inside domain. It connects to the address it
// checked, without looking the name up again in between. Only port 443 is
// connected to. Requests go over HTTPS, with the upstream's certificate
// checked for the name, and redirects are handed back, not followed. A
// request carrying a registered surrogate is refused unsent: nothing here
// swaps it.
//
// What a Sender connected to (or, when it refused, what it found) is told
// to the caller for its record: in a Report for a request, and on the Conn
// for a passthrough.
package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

// Port is the only port a Sender connects to (docs/adr/0008 "ポートは 443
// だけ").
const Port = 443

// Reason names why a request or a connection was not sent or did not get
// an answer. The failures are named as authd names its own
// (docs/authd-protocol.md).
type Reason string

const (
	// Refusals: the Sender did not try.
	ReasonAddressLocal   Reason = "upstream-address-local"
	ReasonAddressPrivate Reason = "upstream-address-private"
	ReasonSurrogate      Reason = "surrogate-unswapped"
	ReasonPort           Reason = "upstream-port"
	ReasonNotHTTPS       Reason = "upstream-not-https"
	// Failures: the upstream could not be reached or did not answer.
	ReasonUnreachable Reason = "upstream-unreachable"
	ReasonCertificate Reason = "upstream-certificate"
	ReasonFailed      Reason = "upstream-failed"
)

// Error is why a Sender did not send or got no answer. Its text never holds
// a surrogate.
type Error struct {
	Reason Reason
	// Resolved are the addresses the name was looked up to, when it was.
	Resolved []netip.Addr
	Message  string
	Err      error
}

func (e *Error) Error() string { return string(e.Reason) + ": " + e.Message }

func (e *Error) Unwrap() error { return e.Err }

// Refused reports whether the Sender refused to send, as against failing
// to.
func (e *Error) Refused() bool {
	switch e.Reason {
	case ReasonUnreachable, ReasonCertificate, ReasonFailed:
		return false
	}
	return true
}

// Report is where a Sender connected, for the caller's record.
type Report struct {
	// Address is the address connected to.
	Address netip.AddrPort
	// Resolved are all the addresses the name was looked up to.
	Resolved []netip.Addr
	// Inside is set for a name under an inside domain, and InsidePublic
	// when such a name was connected to a public address.
	Inside       bool
	InsidePublic bool
}

// Resolver looks names up. *net.Resolver is one.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Config is what a Sender needs.
type Config struct {
	// Inside are the inside domains. None, and no name is connected to a
	// private address.
	Inside Domains
	// Private are more private ranges than the usual ones (RFC 1918,
	// RFC 6598, unique local IPv6), for a cluster whose Pod and Service
	// ranges are elsewhere.
	Private []netip.Prefix
	// Surrogates are authd's: a request carrying one is refused.
	Surrogates Surrogates
	// Resolver defaults to net.DefaultResolver.
	Resolver Resolver
	// DialAddr connects to an address the Sender checked. Defaults to a
	// net.Dialer. Tests replace it.
	DialAddr func(ctx context.Context, network, addr string) (net.Conn, error)
	// RootCAs check the upstreams' certificates. Nil uses the system's
	// (the image's), never the gate's own CA.
	RootCAs *x509.CertPool
}

// Sender sends upstream. It is safe for concurrent use.
type Sender struct {
	cfg Config
	tr  *http.Transport
}

// New makes a Sender.
func New(cfg Config) *Sender {
	if cfg.Resolver == nil {
		cfg.Resolver = net.DefaultResolver
	}
	if cfg.DialAddr == nil {
		cfg.DialAddr = (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}
	s := &Sender{cfg: cfg}
	s.tr = &http.Transport{
		// Never a proxy from the environment.
		Proxy: nil,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			return s.Dial(ctx, host, Port)
		},
		TLSClientConfig: &tls.Config{RootCAs: cfg.RootCAs, MinVersion: tls.VersionTLS12},
		// HTTP/1.1, as authd sends: an empty TLSNextProto turns HTTP/2
		// off.
		ForceAttemptHTTP2:     false,
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
		DisableCompression:    true,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
	}
	return s
}

// Conn is a connection a Sender made, with where it connected.
type Conn struct {
	net.Conn
	Report Report
}

// Dial looks name up and connects to the first of its addresses that may
// be connected to and answers. It is a plain TCP connection: a passthrough
// carries the workspace's own TLS over it.
func (s *Sender) Dial(ctx context.Context, name string, port uint16) (*Conn, error) {
	if port != Port {
		return nil, &Error{Reason: ReasonPort, Message: fmt.Sprintf("port %d; only %d is connected to", port, Port)}
	}
	name = routes.Normalize(name)
	addrs, err := s.cfg.Resolver.LookupNetIP(ctx, "ip", name)
	if err != nil {
		return nil, &Error{Reason: ReasonUnreachable, Message: "the name could not be looked up: " + err.Error(), Err: err}
	}
	rep := Report{Resolved: addrs, Inside: s.cfg.Inside.Inside(name)}
	var (
		allowed      []netip.Addr
		sawLocal     bool
		sawForbidden bool
	)
	for _, a := range addrs {
		switch classify(a, s.cfg.Private) {
		case local:
			sawLocal = true
		case private:
			if !rep.Inside {
				sawForbidden = true
				continue
			}
			allowed = append(allowed, a)
		default:
			allowed = append(allowed, a)
		}
	}
	if len(allowed) == 0 {
		switch {
		case sawForbidden:
			return nil, &Error{Reason: ReasonAddressPrivate, Resolved: addrs, Message: "the name is not under an inside domain, and was looked up to private addresses only"}
		case sawLocal:
			return nil, &Error{Reason: ReasonAddressLocal, Resolved: addrs, Message: "the name was looked up to loopback, link-local or other addresses that are never connected to"}
		}
		return nil, &Error{Reason: ReasonUnreachable, Resolved: addrs, Message: "the name has no addresses"}
	}
	var errs []error
	for _, a := range allowed {
		ap := netip.AddrPortFrom(a.Unmap(), port)
		c, err := s.cfg.DialAddr(ctx, "tcp", ap.String())
		if err != nil {
			errs = append(errs, err)
			continue
		}
		rep.Address = ap
		rep.InsidePublic = rep.Inside && classify(a, s.cfg.Private) == public
		return &Conn{Conn: c, Report: rep}, nil
	}
	err = errors.Join(errs...)
	return nil, &Error{Reason: ReasonUnreachable, Resolved: addrs, Message: "no address of the name could be connected to: " + err.Error(), Err: err}
}

type reportKey struct{}

// WithReport gives a context for a request to RoundTrip, and the Report
// that RoundTrip fills in for it.
func WithReport(ctx context.Context) (context.Context, *Report) {
	rep := &Report{}
	return context.WithValue(ctx, reportKey{}, rep), rep
}

// RoundTrip implements http.RoundTripper. It sends req as it is, to the
// name and port in its URL, adding nothing to it (no compression, no
// User-Agent of its own, no forwarding headers).
//
// The version that moves the requests with keys to the gate swaps the
// surrogate for the key between the checks of the URL and the check for
// surrogates (docs/adr/0007); nothing here swaps one yet.
func (s *Sender) RoundTrip(req *http.Request) (*http.Response, error) {
	rep, _ := req.Context().Value(reportKey{}).(*Report)
	resp, err := s.roundTrip(req, rep)
	if err != nil {
		e := classifyErr(err)
		if rep != nil && rep.Resolved == nil {
			rep.Resolved = e.Resolved
		}
		return nil, e
	}
	return resp, nil
}

func (s *Sender) roundTrip(req *http.Request, rep *Report) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		closeBody(req)
		return nil, &Error{Reason: ReasonNotHTTPS, Message: "only HTTPS is sent"}
	}
	if p := req.URL.Port(); p != "" && p != strconv.Itoa(Port) {
		closeBody(req)
		return nil, &Error{Reason: ReasonPort, Message: fmt.Sprintf("port %s; only %d is connected to", p, Port)}
	}
	if where := s.surrogateIn(req); where != "" {
		closeBody(req)
		return nil, &Error{Reason: ReasonSurrogate, Message: "a registered surrogate is in the request's " + where + ", and nothing swaps it"}
	}

	ctx := req.Context()
	if rep != nil {
		ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) {
				c := info.Conn
				if tc, ok := c.(*tls.Conn); ok {
					c = tc.NetConn()
				}
				if sc, ok := c.(*Conn); ok {
					*rep = sc.Report
				}
			},
		})
	}
	out := req.Clone(ctx)
	if _, ok := out.Header["User-Agent"]; !ok {
		// An empty User-Agent keeps Go's own off the request.
		out.Header.Set("User-Agent", "")
	}
	return s.tr.RoundTrip(out)
}

// surrogateIn says where in req a registered surrogate is: in a header's
// name or value, or in the query, as it came or unescaped. The body is not
// looked in (docs/adr/0003).
func (s *Sender) surrogateIn(req *http.Request) string {
	if s.cfg.Surrogates.Len() == 0 {
		return ""
	}
	for k, vs := range req.Header {
		if s.cfg.Surrogates.In(k) {
			return "headers"
		}
		for _, v := range vs {
			if s.cfg.Surrogates.In(v) {
				return "headers"
			}
		}
	}
	q := req.URL.RawQuery
	if s.cfg.Surrogates.In(q) {
		return "query"
	}
	if u, err := url.QueryUnescape(q); err == nil && s.cfg.Surrogates.In(u) {
		return "query"
	}
	values, _ := url.ParseQuery(q)
	for k, vs := range values {
		if s.cfg.Surrogates.In(k) {
			return "query"
		}
		for _, v := range vs {
			if s.cfg.Surrogates.In(v) {
				return "query"
			}
		}
	}
	return ""
}

func closeBody(req *http.Request) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
}

// classifyErr names a failure the way authd does (docs/authd-protocol.md).
func classifyErr(err error) *Error {
	var ue *Error
	if errors.As(err, &ue) {
		return ue
	}
	var (
		certErr     *tls.CertificateVerificationError
		unknownAuth x509.UnknownAuthorityError
		hostErr     x509.HostnameError
		invalidErr  x509.CertificateInvalidError
	)
	if errors.As(err, &certErr) || errors.As(err, &unknownAuth) || errors.As(err, &hostErr) || errors.As(err, &invalidErr) {
		return &Error{Reason: ReasonCertificate, Message: "the upstream's certificate could not be verified: " + err.Error(), Err: err}
	}
	return &Error{Reason: ReasonFailed, Message: "the exchange with the upstream broke: " + err.Error(), Err: err}
}
