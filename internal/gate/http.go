package gate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/authdclient"
	"github.com/yuanying/natsumi-sentinel/internal/decide"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

const tableHint = "This is set in the gate's routing table; to change it, the owner edits the table."

// serveHTTP takes one request on an open destination: it checks the name,
// decides, records, and hands the request on.
func (g *Gate) serveHTTP(w http.ResponseWriter, r *http.Request) {
	oc, _ := r.Context().Value(connKey{}).(*openConn)
	if oc == nil {
		writeGate(w, http.StatusInternalServerError, MarkError, "the connection was not set up by the gate")
		return
	}
	oc.mu.Lock()
	oc.served = true
	oc.mu.Unlock()

	rec := g.base(audit.KindHTTP, oc.dst)
	rec.Treatment = string(routes.Open)
	rec.Name = oc.sni
	rec.Method = r.Method
	rec.Path = r.URL.Path
	rec.Query = r.URL.RawQuery

	// Reads keep their fields only (docs/adr/0006): no text of the body.
	var limit int64
	if isWrite(r.Method) {
		limit = g.cfg.Routes().Audit().BodyLimit
	}
	capture, body, err := audit.CaptureBody(r.Body, limit)
	if err != nil {
		rec.Error = err.Error()
		g.refuse(w, rec, http.StatusBadRequest, MarkError, "the request body could not be read")
		return
	}
	rec.Request = summary(capture)

	if reason := g.checkName(r, oc); reason != "" {
		g.refuse(w, rec, http.StatusForbidden, MarkDeny, reason)
		return
	}
	if isUpgrade(r) {
		g.refuse(w, rec, http.StatusNotImplemented, MarkDeny, "upgrades (WebSocket and the like) are not opened by this version of the gate")
		return
	}
	if r.Method == http.MethodConnect {
		g.refuse(w, rec, http.StatusMethodNotAllowed, MarkDeny, "CONNECT is not opened")
		return
	}

	prefix := capture.Summary()
	table := g.cfg.Routes()
	decision := g.cfg.Decider.Decide(r.Context(), decide.Request{
		Source:       g.cfg.Source,
		Destination:  oc.dest,
		Settings:     table.Approvals(),
		Port:         oc.dst.Port(),
		Method:       r.Method,
		Path:         r.URL.Path,
		Query:        r.URL.RawQuery,
		Header:       r.Header.Clone(),
		Body:         capture.Prefix(),
		BodyComplete: !prefix.Truncated,
		BodySummary:  summary(capture),
	})
	rec.Reason = decision.Reason
	rec.Operation = decision.Operation
	rec.Target = decision.Target
	rec.Approval = decision.Approval
	rec.Grant = decision.Grant
	switch {
	case decision.Error != "":
		rec.Error = decision.Error
		g.refuse(w, rec, http.StatusServiceUnavailable, MarkError, "the request was not sent: "+decision.Reason)
		return
	case decision.Verdict == audit.Ask:
		g.ask(w, rec, decision)
		return
	case decision.Verdict != audit.Allow:
		g.refuse(w, rec, http.StatusForbidden, MarkDeny, "denied: "+decision.Reason+". "+tableHint)
		return
	}
	rec.Verdict = audit.Allow

	// Nothing goes out unrecorded (docs/adr/0006).
	if err := g.cfg.Log.Begin(r.Context(), rec); err != nil {
		g.cfg.Logger.Error("a request could not be recorded, so it was not sent", "name", rec.Name, "error", err)
		writeGate(w, http.StatusServiceUnavailable, MarkError, "the audit record could not be written, so the request was not sent")
		return
	}
	start := g.cfg.Now()
	defer func() {
		rec.Duration = g.cfg.Now().Sub(start)
		rec.Request = summary(capture)
		// The request's own context may be gone by now.
		if err := g.cfg.Log.Finish(context.Background(), rec); err != nil {
			g.cfg.Logger.Error("a request's record could not be finished", "id", rec.ID, "error", err)
		}
	}()

	out := outgoing(r, oc, body)
	resp, err := g.cfg.Upstream.RoundTrip(out)
	if err != nil {
		text := upstreamFailure(rec, err)
		writeGate(w, http.StatusBadGateway, MarkError, text)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	h := w.Header()
	for k, vs := range resp.Header {
		h[k] = vs
	}
	removeHopByHop(h)
	h.Del(MarkHeader)
	h.Del(ApprovalHeader)
	w.WriteHeader(resp.StatusCode)
	rec.Status = resp.StatusCode
	n, err := copyFlushing(w, resp.Body)
	rec.ResponseBytes = n
	if err != nil {
		rec.Error = "the response was cut off: " + err.Error()
	}
}

// upstreamFailure puts why the request did not get an upstream's answer
// into the record, and gives the text to answer the workspace with. authd's
// own answers carry a reason and say whether authd refused or failed to
// reach the upstream (docs/authd-protocol.md). Anything else means authd
// itself could not be reached: the request was not sent (docs/adr/0001).
func upstreamFailure(rec *audit.Record, err error) string {
	var ae *authdclient.Error
	if !errors.As(err, &ae) {
		rec.Error = "authd could not be reached: " + err.Error()
		return "the request was not sent: authd could not be reached"
	}
	rec.AuthdReason = string(ae.Reason)
	what := "authd could not get an answer from the upstream"
	if ae.Refused() {
		what = "authd refused the request"
	}
	rec.Error = fmt.Sprintf("%s: %s: %s", what, ae.Reason, ae.Message)
	return fmt.Sprintf("%s (%s): %s", what, ae.Reason, ae.Message)
}

// ask records a request held for the owner and answers it at once: the
// connection is not kept open for the answer (docs/adr/0004).
func (g *Gate) ask(w http.ResponseWriter, rec *audit.Record, d decide.Decision) {
	rec.Verdict = audit.Ask
	rec.Status = http.StatusForbidden
	if err := g.cfg.Log.Write(context.Background(), rec); err != nil {
		g.cfg.Logger.Error("a held request could not be recorded", "name", rec.Name, "error", err)
	}
	what := "a request no rule names"
	if d.Operation != "" {
		what = "the operation " + d.Operation
		if d.Target != "" {
			what += " (" + d.Target + ")"
		}
	}
	text := fmt.Sprintf("held for the owner's answer as approval %s: %s. Once the owner allows it, make the same request again.", d.Approval, what)
	if g.cfg.StatusURL != "" {
		text += " Your approvals and grants are at " + g.cfg.StatusURL + "."
	}
	w.Header().Set(ApprovalHeader, d.Approval)
	writeGate(w, http.StatusForbidden, MarkAsk, text)
}

// refuse records a request the gate answers itself and answers it.
func (g *Gate) refuse(w http.ResponseWriter, rec *audit.Record, status int, mark, text string) {
	rec.Verdict = audit.Deny
	if rec.Reason == "" {
		rec.Reason = text
	}
	rec.Status = status
	if err := g.cfg.Log.Write(context.Background(), rec); err != nil {
		g.cfg.Logger.Error("a refused request could not be recorded", "name", rec.Name, "error", err)
	}
	writeGate(w, status, mark, text)
}

// checkName holds the request's Host to the connection's SNI: the gate
// decided on the SNI, and the request has to be for the same name and
// port (docs/adr/0002).
func (g *Gate) checkName(r *http.Request, oc *openConn) string {
	if r.Host == "" {
		return "the request has no Host; the gate decides by name"
	}
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		host, port = r.Host, ""
	}
	if routes.Normalize(host) != oc.sni {
		return fmt.Sprintf("the Host (%s) is not the name the connection was opened for (%s)", host, oc.sni)
	}
	if port != "" && port != strconv.Itoa(int(oc.dst.Port())) {
		return fmt.Sprintf("the Host's port (%s) is not the port the connection was made to (%d)", port, oc.dst.Port())
	}
	return ""
}

// outgoing is the request handed on: to the name and port the gate decided
// on, with the headers as they came apart from the hop-by-hop ones. The
// surrogate stays where the tool put it; authd swaps it.
func outgoing(r *http.Request, oc *openConn, body io.Reader) *http.Request {
	out := r.Clone(r.Context())
	out.URL = &url.URL{
		Scheme:   "https",
		Host:     net.JoinHostPort(oc.sni, strconv.Itoa(int(oc.dst.Port()))),
		Path:     r.URL.Path,
		RawPath:  r.URL.RawPath,
		RawQuery: r.URL.RawQuery,
	}
	out.Host = r.Host
	out.RequestURI = ""
	removeHopByHop(out.Header)
	// The body is already being read; there is nothing to wait for.
	out.Header.Del("Expect")
	if r.ContentLength == 0 {
		out.Body = http.NoBody
	} else {
		out.Body = io.NopCloser(body)
	}
	return out
}

// copyFlushing copies the response on as it arrives, so that a follow or
// a watch reaches the client without waiting for the end.
func copyFlushing(w http.ResponseWriter, body io.Reader) (int64, error) {
	rc := http.NewResponseController(w)
	buf := make([]byte, 32<<10)
	var total int64
	for {
		n, err := body.Read(buf)
		if n > 0 {
			m, werr := w.Write(buf[:n])
			total += int64(m)
			if werr != nil {
				return total, werr
			}
			_ = rc.Flush()
		}
		if errors.Is(err, io.EOF) {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

func summary(c *audit.BodyCapture) *audit.Body {
	s := c.Summary()
	if s.Size == 0 && !s.Truncated {
		return nil
	}
	return &s
}

func isWrite(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return false
	}
	return true
}

func isUpgrade(r *http.Request) bool {
	return r.Header.Get("Upgrade") != "" || hasToken(r.Header, "Connection", "upgrade")
}

func hasToken(h http.Header, key, token string) bool {
	for _, v := range h.Values(key) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

var hopByHop = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func removeHopByHop(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, t := range strings.Split(v, ",") {
			if t = strings.TrimSpace(t); t != "" {
				h.Del(textproto.CanonicalMIMEHeaderKey(t))
			}
		}
	}
	for _, k := range hopByHop {
		h.Del(k)
	}
}
