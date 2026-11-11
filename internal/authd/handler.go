package authd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/authdclient"
)

// Options are what NewHandler takes besides the registration.
type Options struct {
	// Logger receives one line for each request authd refuses or cannot
	// send. It never receives a key or a surrogate. Nil discards.
	Logger *slog.Logger
	// DialContext connects to an upstream by the name and port the gate
	// gave. Nil uses the system's resolver and a plain TCP dial.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

type handler struct {
	log *slog.Logger
	// routes is keyed by "name:port".
	routes      map[string]*route
	bySurrogate map[string]*credential
	// places is every place registered for any surrogate: the only places
	// authd looks in.
	places []place
}

type route struct {
	authority string
	upstream  *upstream
	proxy     *httputil.ReverseProxy
}

// NewHandler returns the handler authd serves on its socket. Each request's
// Host is the upstream's name and port, as the gate decided them; its path,
// query, headers and body are the workspace's, with surrogates as they were.
func NewHandler(cfg *Config, opts Options) (http.Handler, error) {
	h := &handler{
		log:         opts.Logger,
		routes:      map[string]*route{},
		bySurrogate: map[string]*credential{},
	}
	if h.log == nil {
		h.log = slog.New(slog.DiscardHandler)
	}
	dial := opts.DialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}
	for _, c := range cfg.credentials {
		h.bySurrogate[c.surrogate] = c
		for _, p := range c.places {
			if !slices.Contains(h.places, p) {
				h.places = append(h.places, p)
			}
		}
	}
	for _, u := range cfg.upstreams {
		for _, port := range u.ports {
			authority := net.JoinHostPort(u.name, strconv.Itoa(port))
			if h.routes[authority] != nil {
				continue
			}
			h.routes[authority] = h.newRoute(u, port, dial)
		}
	}
	return h, nil
}

func (h *handler) newRoute(u *upstream, port int, dial func(ctx context.Context, network, addr string) (net.Conn, error)) *route {
	authority := net.JoinHostPort(u.name, strconv.Itoa(port))
	host := authority
	if port == 443 {
		host = u.name
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
	}
	tr := &http.Transport{
		// Never a proxy from the environment.
		Proxy:       nil,
		DialContext: dial,
		TLSClientConfig: &tls.Config{
			ServerName: u.name,
			RootCAs:    u.roots,
			MinVersion: tls.VersionTLS12,
		},
		// HTTP/1.1 to the upstream: an empty TLSNextProto turns HTTP/2
		// off. Upgrades (WebSocket, SPDY) work on HTTP/1.1.
		ForceAttemptHTTP2:     false,
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
		DisableCompression:    true,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
	}
	r := &route{authority: authority, upstream: u}
	r.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "https"
			pr.Out.URL.Host = host
			pr.Out.Host = ""
		},
		Transport: tr,
		// Hand on each piece as it arrives: watches, logs -f, clones.
		FlushInterval: -1,
		ModifyResponse: func(resp *http.Response) error {
			// Only authd may say it refused.
			resp.Header.Del(authdclient.ErrorHeader)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			h.upstreamError(w, req, r, err)
		},
		ErrorLog: slog.NewLogLogger(h.log.Handler(), slog.LevelWarn),
	}
	return r
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	authority, ok := parseAuthority(r.Host)
	if !ok {
		h.refuse(w, "", authdclient.ReasonBadRequest, "the request does not name an upstream as name:port")
		return
	}
	rt := h.routes[authority]
	if rt == nil {
		h.refuse(w, authority, authdclient.ReasonUpstreamNotRegistered, "the upstream is not registered")
		return
	}
	if reason, msg := h.swap(r, rt.upstream.name); reason != "" {
		h.refuse(w, authority, reason, msg)
		return
	}
	rt.proxy.ServeHTTP(w, r)
}

// parseAuthority turns the Host the gate sent into "name:port", with the
// name in lower case. A Host without a port means 443.
func parseAuthority(host string) (string, bool) {
	if host == "" {
		return "", false
	}
	name, port, err := net.SplitHostPort(host)
	if err != nil {
		name, port = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"), "443"
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || name == "" {
		return "", false
	}
	return net.JoinHostPort(strings.ToLower(name), port), true
}

// edit is one surrogate found in a registered place, to be swapped.
type edit struct {
	place place
	// header: the index of the value among the header's values.
	// query: the index of the part among the query's &-separated parts.
	index int
	cred  *credential
}

// swap looks for registered surrogates in the registered places of r, checks
// each against the registration, and swaps them for their real keys in r. It
// changes nothing and returns a reason when the request is to be refused.
func (h *handler) swap(r *http.Request, upstreamName string) (authdclient.Reason, string) {
	var edits []edit
	var queryParts []string
	if r.URL.RawQuery != "" {
		queryParts = strings.Split(r.URL.RawQuery, "&")
	}
	for _, p := range h.places {
		switch p.kind {
		case placeBearer, placeBasic:
			for i, v := range r.Header.Values("Authorization") {
				if s, ok := surrogateInAuthorization(p, v); ok {
					if c := h.bySurrogate[s]; c != nil {
						edits = append(edits, edit{place: p, index: i, cred: c})
					}
				}
			}
		case placeHeader:
			for i, v := range r.Header.Values(p.name) {
				if c := h.bySurrogate[strings.TrimSpace(v)]; c != nil {
					edits = append(edits, edit{place: p, index: i, cred: c})
				}
			}
		case placeQuery:
			for i, part := range queryParts {
				k, v, _ := strings.Cut(part, "=")
				if key, err := url.QueryUnescape(k); err != nil || key != p.name {
					continue
				}
				if val, err := url.QueryUnescape(v); err == nil {
					if c := h.bySurrogate[val]; c != nil {
						edits = append(edits, edit{place: p, index: i, cred: c})
					}
				}
			}
		}
	}

	keys := map[*credential]string{}
	for _, e := range edits {
		if !e.cred.upstreams[upstreamName] {
			return authdclient.ReasonSurrogateMismatch, "a surrogate is not registered for this upstream"
		}
		if !e.cred.has(e.place) {
			return authdclient.ReasonSurrogateMismatch, "a surrogate is in a place that is not registered for it"
		}
		if _, ok := keys[e.cred]; ok {
			continue
		}
		key, err := readKey(e.cred.keyFile)
		if err != nil {
			h.log.Error("cannot read a real key", "credential", e.cred.index, "error", err.Error())
			return authdclient.ReasonCredentialUnavailable, "the real key for the surrogate cannot be read"
		}
		keys[e.cred] = key
	}

	header := r.Header.Clone()
	for _, e := range edits {
		key := keys[e.cred]
		switch e.place.kind {
		case placeBearer:
			header["Authorization"][e.index] = e.place.name + " " + key
		case placeBasic:
			user, _ := basicUser(r.Header.Values("Authorization")[e.index])
			header["Authorization"][e.index] = "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+key))
		case placeHeader:
			header[e.place.name][e.index] = key
		case placeQuery:
			k, _, _ := strings.Cut(queryParts[e.index], "=")
			queryParts[e.index] = k + "=" + url.QueryEscape(key)
		}
	}
	rawQuery := strings.Join(queryParts, "&")

	// Whatever is left must hold no surrogate: one outside the registered
	// places is not sent on as it is (docs/adr/0003). The body is not
	// looked at.
	if h.holdsSurrogate(header, rawQuery) {
		return authdclient.ReasonSurrogateMismatch, "a surrogate is in a place that is not registered for it"
	}
	r.Header = header
	r.URL.RawQuery = rawQuery
	return "", ""
}

// surrogateInAuthorization returns the candidate surrogate in an
// Authorization value for a bearer or basic place.
func surrogateInAuthorization(p place, v string) (string, bool) {
	scheme, rest, ok := strings.Cut(strings.TrimSpace(v), " ")
	if !ok {
		return "", false
	}
	rest = strings.TrimSpace(rest)
	switch p.kind {
	case placeBearer:
		if strings.EqualFold(scheme, p.name) {
			return rest, true
		}
	case placeBasic:
		if strings.EqualFold(scheme, "Basic") {
			b, err := base64.StdEncoding.DecodeString(rest)
			if err != nil {
				return "", false
			}
			_, pass, ok := strings.Cut(string(b), ":")
			return pass, ok
		}
	}
	return "", false
}

func basicUser(v string) (string, bool) {
	_, rest, _ := strings.Cut(strings.TrimSpace(v), " ")
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest))
	if err != nil {
		return "", false
	}
	user, _, ok := strings.Cut(string(b), ":")
	return user, ok
}

func (h *handler) holdsSurrogate(header http.Header, rawQuery string) bool {
	if len(h.bySurrogate) == 0 {
		return false
	}
	var hay []string
	for _, vs := range header {
		for _, v := range vs {
			hay = append(hay, v)
			if scheme, rest, ok := strings.Cut(strings.TrimSpace(v), " "); ok && strings.EqualFold(scheme, "Basic") {
				if b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest)); err == nil {
					hay = append(hay, string(b))
				}
			}
		}
	}
	hay = append(hay, rawQuery)
	if q, err := url.QueryUnescape(rawQuery); err == nil {
		hay = append(hay, q)
	}
	for _, s := range hay {
		for sur := range h.bySurrogate {
			if strings.Contains(s, sur) {
				return true
			}
		}
	}
	return false
}

func (h *handler) refuse(w http.ResponseWriter, authority string, reason authdclient.Reason, msg string) {
	h.log.Info("refused", "upstream", authority, "reason", string(reason))
	authdclient.WriteError(w, &authdclient.Error{Reason: reason, Message: msg})
}

// upstreamError answers for a request the upstream could not be asked. Its
// message and log line are made from the kind of failure only: the error's
// own text could carry the URL, and the URL a key.
func (h *handler) upstreamError(w http.ResponseWriter, r *http.Request, rt *route, err error) {
	if errors.Is(err, context.Canceled) && r.Context().Err() != nil {
		// The gate went away; there is no one to answer.
		return
	}
	reason, msg := classify(err)
	h.log.Warn("upstream failed", "upstream", rt.authority, "reason", string(reason))
	authdclient.WriteError(w, &authdclient.Error{Reason: reason, Message: msg})
}

func classify(err error) (authdclient.Reason, string) {
	var certErr *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var invalidErr x509.CertificateInvalidError
	var dnsErr *net.DNSError
	var opErr *net.OpError
	switch {
	case errors.As(err, &certErr), errors.As(err, &unknownAuthority), errors.As(err, &hostnameErr), errors.As(err, &invalidErr):
		return authdclient.ReasonUpstreamCertificate, "the upstream's certificate did not verify"
	case errors.As(err, &dnsErr):
		return authdclient.ReasonUpstreamUnreachable, "the upstream's name did not resolve"
	case errors.As(err, &opErr) && opErr.Op == "dial":
		return authdclient.ReasonUpstreamUnreachable, "the connection to the upstream could not be made"
	default:
		return authdclient.ReasonUpstreamFailed, "the exchange with the upstream failed"
	}
}
