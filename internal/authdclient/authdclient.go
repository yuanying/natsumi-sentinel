// Package authdclient is the gate's side of the link to authd, and the
// contract between the two.
//
// The gate hands every request it has decided on to authd, surrogate and all
// (docs/adr/0003). Transport is the http.RoundTripper that does so: it takes
// a request whose URL is https://<name>:<port>/..., where name and port are
// what the gate decided on, and sends it over authd's Unix socket. When authd
// refuses the request, or cannot reach the upstream, RoundTrip returns an
// *Error that carries the reason, so that the gate can record it.
//
// The contract lives here rather than in authd's own package so that the gate
// needs nothing from authd's side. This package reads no keys, and must not
// import anything that does: the gate's binary is not to carry key-reading
// code (docs/adr/0001).
package authdclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// ErrorHeader marks a response that authd made itself, rather than one it
// passed on from the upstream. Its value is the Reason. authd removes the
// same header from upstream responses, so its presence is authd's word.
const ErrorHeader = "Authd-Error"

// Reason says why authd did not hand back an upstream's response.
type Reason string

// The reasons authd refuses a request: its own checks failed, and nothing was
// sent to the upstream (docs/adr/0003, "authd も自分で確かめ").
const (
	// ReasonUpstreamNotRegistered: the name and port are not registered.
	ReasonUpstreamNotRegistered Reason = "upstream-not-registered"
	// ReasonSurrogateMismatch: a surrogate was found that is not registered
	// for this upstream, or not for the place it was found in.
	ReasonSurrogateMismatch Reason = "surrogate-mismatch"
	// ReasonCredentialUnavailable: the real key for the surrogate could not
	// be read.
	ReasonCredentialUnavailable Reason = "credential-unavailable"
	// ReasonBadRequest: the request did not have the form the gate is to
	// send. This is a fault in the gate, not in the workspace.
	ReasonBadRequest Reason = "bad-request"
)

// The reasons authd could not get a response from the upstream after its
// checks passed.
const (
	// ReasonUpstreamUnreachable: the name did not resolve or the connection
	// could not be made.
	ReasonUpstreamUnreachable Reason = "upstream-unreachable"
	// ReasonUpstreamCertificate: the upstream's certificate did not verify.
	ReasonUpstreamCertificate Reason = "upstream-certificate"
	// ReasonUpstreamFailed: the exchange with the upstream failed in some
	// other way.
	ReasonUpstreamFailed Reason = "upstream-failed"
)

// Error is a response authd made itself. Message is a sentence for the record
// and never holds a key or a surrogate.
type Error struct {
	Reason  Reason `json:"reason"`
	Message string `json:"message"`
}

func (e *Error) Error() string {
	if e.Message == "" {
		return "authd: " + string(e.Reason)
	}
	return fmt.Sprintf("authd: %s: %s", e.Reason, e.Message)
}

// Refused reports whether authd turned the request down by its own checks,
// as opposed to failing to reach the upstream. A reason this package does not
// know is counted as a refusal.
func (e *Error) Refused() bool {
	switch e.Reason {
	case ReasonUpstreamUnreachable, ReasonUpstreamCertificate, ReasonUpstreamFailed:
		return false
	default:
		return true
	}
}

// status is the HTTP status authd answers with for each reason. The gate does
// not pass it on: it reads the Error.
func (e *Error) status() int {
	switch e.Reason {
	case ReasonBadRequest:
		return http.StatusBadRequest
	case ReasonUpstreamUnreachable, ReasonUpstreamCertificate, ReasonUpstreamFailed:
		return http.StatusBadGateway
	default:
		return http.StatusForbidden
	}
}

// WriteError writes e as authd's own response. It is for authd's side.
func WriteError(w http.ResponseWriter, e *Error) {
	h := w.Header()
	h.Set(ErrorHeader, string(e.Reason))
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(e.status())
	_ = json.NewEncoder(w).Encode(e)
}

// maxErrorBody bounds how much of authd's own error response is read.
const maxErrorBody = 8 << 10

// Transport sends requests to the upstream through authd's Unix socket.
type Transport struct {
	inner *http.Transport
}

// NewTransport returns a Transport that talks to authd at socketPath. It
// connects on first use; a missing socket shows up as RoundTrip's error.
func NewTransport(socketPath string) *Transport {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return &Transport{inner: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		},
		// Never a proxy from the environment: the only way out is authd.
		Proxy: nil,
		// Pass on the workspace's Accept-Encoding as it is, and the
		// upstream's encoded body as it is.
		DisableCompression: true,
		// HTTP/1.1 only, over the socket. Upgrades go through as they are.
		ForceAttemptHTTP2: false,
		MaxIdleConns:      64,
		// All requests go to the one socket, but the pool is kept per
		// upstream name.
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     90 * time.Second,
	}}
}

// RoundTrip sends req to authd. req's URL must be https with the upstream's
// name, and req.Host, if set, must name the same host. The request is passed
// on with its headers, query and body as they are; authd swaps the
// surrogates.
//
// When authd answers with its own error, RoundTrip returns an *Error and no
// response. Any other error means authd could not be reached or the exchange
// with it broke.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	authority, err := upstreamAuthority(req)
	if err != nil {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, err
	}
	out := req.Clone(req.Context())
	u := *req.URL
	u.Scheme = "http"
	u.Host = authority
	out.URL = &u
	out.Host = ""
	resp, err := t.inner.RoundTrip(out)
	if err != nil {
		return nil, err
	}
	if resp.Header.Get(ErrorHeader) == "" {
		return resp, nil
	}
	return nil, readError(resp)
}

// CloseIdleConnections closes the idle connections to authd.
func (t *Transport) CloseIdleConnections() {
	t.inner.CloseIdleConnections()
}

func upstreamAuthority(req *http.Request) (string, error) {
	if req.URL == nil || req.URL.Scheme != "https" {
		return "", errors.New("authdclient: the request URL must be https")
	}
	name := req.URL.Hostname()
	if name == "" {
		return "", errors.New("authdclient: the request URL has no host")
	}
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}
	if req.Host != "" {
		h := req.Host
		if hn, _, err := net.SplitHostPort(h); err == nil {
			h = hn
		}
		h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
		if !strings.EqualFold(h, name) {
			return "", errors.New("authdclient: the request's Host differs from its URL")
		}
	}
	return net.JoinHostPort(name, port), nil
}

func readError(resp *http.Response) error {
	defer func() { _ = resp.Body.Close() }()
	e := &Error{}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	if err := json.Unmarshal(b, e); err != nil || e.Reason == "" {
		e = &Error{}
	}
	e.Reason = Reason(resp.Header.Get(ErrorHeader))
	return e
}
