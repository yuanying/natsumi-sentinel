package gate_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/authdclient"
	"github.com/yuanying/natsumi-sentinel/internal/certs"
	"github.com/yuanying/natsumi-sentinel/internal/decide"
	"github.com/yuanying/natsumi-sentinel/internal/gate"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
	"github.com/yuanying/natsumi-sentinel/internal/testca"
)

// memLog keeps records in memory and can be made to fail.
type memLog struct {
	mu      sync.Mutex
	records []*audit.Record
	fail    bool
	nextID  int64
	changed chan struct{}
}

func newMemLog() *memLog { return &memLog{changed: make(chan struct{}, 100)} }

func (m *memLog) keep(rec *audit.Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return errors.New("disk full")
	}
	m.nextID++
	rec.ID = m.nextID
	cp := *rec
	m.records = append(m.records, &cp)
	m.changed <- struct{}{}
	return nil
}

func (m *memLog) Write(_ context.Context, rec *audit.Record) error {
	rec.Finished = true
	return m.keep(rec)
}

func (m *memLog) Begin(_ context.Context, rec *audit.Record) error {
	rec.Finished = false
	return m.keep(rec)
}

func (m *memLog) Finish(_ context.Context, rec *audit.Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec.Finished = true
	for i, r := range m.records {
		if r.ID == rec.ID {
			cp := *rec
			m.records[i] = &cp
		}
	}
	m.changed <- struct{}{}
	return nil
}

// waitFor waits until a finished record satisfies ok and returns it.
func (m *memLog) waitFor(t *testing.T, ok func(*audit.Record) bool) *audit.Record {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		m.mu.Lock()
		for _, r := range m.records {
			if r.Finished && ok(r) {
				m.mu.Unlock()
				return r
			}
		}
		m.mu.Unlock()
		select {
		case <-m.changed:
		case <-deadline:
			m.mu.Lock()
			defer m.mu.Unlock()
			var got []string
			for _, r := range m.records {
				got = append(got, fmt.Sprintf("%+v", *r))
			}
			t.Fatalf("no such record; have:\n%s", strings.Join(got, "\n"))
			return nil
		}
	}
}

// upstream stands in for authd: it receives what the gate hands on and
// sends it to a test server.
type upstream struct {
	srv  *httptest.Server
	mu   sync.Mutex
	seen []*http.Request
	err  error
}

func (u *upstream) RoundTrip(req *http.Request) (*http.Response, error) {
	u.mu.Lock()
	u.seen = append(u.seen, req.Clone(context.Background()))
	err := u.err
	u.mu.Unlock()
	if err != nil {
		return nil, err
	}
	out := req.Clone(req.Context())
	target, _ := url.Parse(u.srv.URL)
	out.URL.Scheme, out.URL.Host = target.Scheme, target.Host
	return http.DefaultTransport.RoundTrip(out)
}

func (u *upstream) requests() []*http.Request {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]*http.Request(nil), u.seen...)
}

type env struct {
	t        *testing.T
	ca       *testca.CA
	log      *memLog
	up       *upstream
	addr     string // where the gate listens
	origDst  netip.AddrPort
	mu       sync.Mutex
	decider  decide.Decider
	upstream http.Handler
}

const table = `
destinations:
  - name: api.example.com
    treatment: open
    default: allow
  - name: closed.example.com
    treatment: open
    default: deny
  - name: blocked.example.com
    treatment: deny
passthrough:
  - cidr: 127.0.0.0/8
    ports: [%[1]d]
  - cidr: ::1/128
    ports: [%[1]d]
audit:
  bodyLimitBytes: 16
`

func newEnv(t *testing.T, passthroughPort int) *env {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "routes.yaml"), fmt.Appendf(nil, table, passthroughPort), 0o600); err != nil {
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
	e := &env{t: t, ca: ca, log: newMemLog(), origDst: netip.MustParseAddrPort("192.0.2.10:443")}
	e.upstream = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(gate.MarkHeader, "forged")
		w.Header().Set(gate.ApprovalHeader, "forged")
		w.Header().Set("X-Upstream", "yes")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "from upstream")
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		h := e.upstream
		e.mu.Unlock()
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	e.up = &upstream{srv: srv}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e.addr = ln.Addr().String()
	g := gate.New(gate.Config{
		Source:   "workspace",
		Routes:   w.Current,
		Decider:  deciderFunc(e.decide),
		Minter:   minter,
		Log:      e.log,
		Upstream: e.up,
		OriginalDst: func(net.Conn) (netip.AddrPort, error) {
			e.mu.Lock()
			defer e.mu.Unlock()
			if !e.origDst.IsValid() {
				return netip.AddrPort{}, errors.New("not redirected")
			}
			return e.origDst, nil
		},
		FirstByteTimeout: time.Second,
		StatusURL:        "http://sentinel.internal/v1/status",
		AgentAddr:        netip.MustParseAddrPort("192.0.2.53:80"),
		Agent: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "the agent door: "+r.Method+" "+r.URL.Path)
		}),
	})
	go func() { _ = g.Serve(ln) }()
	t.Cleanup(func() { _ = g.Close() })
	return e
}

type deciderFunc func(context.Context, decide.Request) decide.Decision

func (f deciderFunc) Decide(ctx context.Context, r decide.Request) decide.Decision { return f(ctx, r) }

func (e *env) decide(ctx context.Context, r decide.Request) decide.Decision {
	e.mu.Lock()
	d := e.decider
	e.mu.Unlock()
	if d == nil {
		d = decide.Table{}
	}
	return d.Decide(ctx, r)
}

func (e *env) setOrigDst(s string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if s == "" {
		e.origDst = netip.AddrPort{}
		return
	}
	e.origDst = netip.MustParseAddrPort(s)
}

func (e *env) setUpstream(h http.HandlerFunc) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.upstream = h
}

// client talks to the gate as the workspace would: to the real URL, with
// every connection landing on the gate.
func (e *env) client() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, e.addr)
			},
			TLSClientConfig:   &tls.Config{RootCAs: e.ca.Pool()},
			DisableKeepAlives: true,
		},
		Timeout: 10 * time.Second,
	}
}

func TestAnAllowedRequestIsHandedOnByNameWithItsKeyAndTheAnswerComesBack(t *testing.T) {
	e := newEnv(t, 1)
	req, _ := http.NewRequest("POST", "https://api.example.com/repos/o/r/issues?state=open", strings.NewReader(`{"title":"hi"}`))
	req.Header.Set("Authorization", "Bearer surrogate-value")
	resp, err := e.client().Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated || string(body) != "from upstream" {
		t.Errorf("response = %d %q, want 201 from upstream", resp.StatusCode, body)
	}
	if resp.Header.Get("X-Upstream") != "yes" {
		t.Error("the upstream's headers did not come back")
	}
	for _, h := range []string{gate.MarkHeader, gate.ApprovalHeader} {
		if got := resp.Header.Get(h); got != "" {
			t.Errorf("the upstream's %s: %q came back; it must be removed", h, got)
		}
	}

	seen := e.up.requests()
	if len(seen) != 1 {
		t.Fatalf("upstream saw %d requests, want 1", len(seen))
	}
	if got, want := seen[0].URL.String(), "https://api.example.com:443/repos/o/r/issues?state=open"; got != want {
		t.Errorf("handed on to %s, want %s", got, want)
	}
	if got := seen[0].Header.Get("Authorization"); got != "Bearer surrogate-value" {
		t.Errorf("Authorization handed on = %q, want the surrogate as it came", got)
	}

	rec := e.log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindHTTP })
	if rec.Source != "workspace" || rec.Name != "api.example.com" || rec.Address != "192.0.2.10:443" ||
		rec.Method != "POST" || rec.Path != "/repos/o/r/issues" || rec.Query != "state=open" ||
		rec.Verdict != audit.Allow || rec.Status != 201 || rec.ResponseBytes != int64(len("from upstream")) ||
		rec.Treatment != "open" {
		t.Errorf("record = %+v", rec)
	}
	if rec.Request == nil || rec.Request.Text != `{"title":"hi"}` || rec.Request.SHA256 == "" {
		t.Errorf("record's body = %+v, want the text and its hash", rec.Request)
	}
}

func TestAReadKeepsOnlyItsFields(t *testing.T) {
	e := newEnv(t, 1)
	resp, err := e.client().Get("https://api.example.com/a?b=c")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	rec := e.log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindHTTP })
	if !rec.Read {
		t.Errorf("record = %+v, want a read", rec)
	}
	if rec.Request != nil && rec.Request.Text != "" {
		t.Errorf("a read kept a body: %+v", rec.Request)
	}
	if rec.Query != "b=c" || rec.Status != 201 {
		t.Errorf("record = %+v", rec)
	}
}

func TestABodyPastTheLimitIsSentWholeAndKeptAsItsStartSizeAndHash(t *testing.T) {
	e := newEnv(t, 1)
	var got []byte
	e.setUpstream(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
	})
	body := strings.Repeat("x", 100)
	resp, err := e.client().Post("https://api.example.com/upload", "text/plain", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if string(got) != body {
		t.Errorf("upstream got %d bytes, want %d", len(got), len(body))
	}
	rec := e.log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindHTTP })
	if rec.Request == nil || rec.Request.Text != strings.Repeat("x", 16) || !rec.Request.Truncated || rec.Request.Size != 100 || rec.Request.SHA256 == "" {
		t.Errorf("record's body = %+v", rec.Request)
	}
}

func TestADeniedRequestIsAnsweredByTheGateWithItsMarkAndNotHandedOn(t *testing.T) {
	e := newEnv(t, 1)
	resp, err := e.client().Post("https://closed.example.com/x", "text/plain", strings.NewReader("data"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if resp.Header.Get(gate.MarkHeader) == "" {
		t.Errorf("the gate's refusal has no %s", gate.MarkHeader)
	}
	if !strings.Contains(string(body), "routing table") {
		t.Errorf("body = %q, want it to say the routing table decides", body)
	}
	if n := len(e.up.requests()); n != 0 {
		t.Errorf("upstream saw %d requests, want none", n)
	}
	rec := e.log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindHTTP })
	if rec.Verdict != audit.Deny || rec.Reason == "" || rec.Request == nil || rec.Request.Text != "data" {
		t.Errorf("record = %+v", rec)
	}
}

func TestAnAskedRequestIsHeldWithTheGatesMarkAndTheApprovalAndNotHandedOn(t *testing.T) {
	e := newEnv(t, 1)
	e.mu.Lock()
	e.decider = deciderFunc(func(context.Context, decide.Request) decide.Decision {
		return decide.Decision{Verdict: audit.Ask, Reason: "asked", Operation: "pulls.merge", Target: "owner=o repo=r", Approval: "ap-1", ApprovalCreated: true}
	})
	e.mu.Unlock()
	resp, err := e.client().Post("https://api.example.com/repos/o/r/pulls/5/merge", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get(gate.MarkHeader) != gate.MarkAsk {
		t.Errorf("response = %d with mark %q, want 403 %s", resp.StatusCode, resp.Header.Get(gate.MarkHeader), gate.MarkAsk)
	}
	if got := resp.Header.Get(gate.ApprovalHeader); got != "ap-1" {
		t.Errorf("%s = %q, want ap-1", gate.ApprovalHeader, got)
	}
	for _, want := range []string{"ap-1", "pulls.merge", "owner=o repo=r", "same request again", "http://sentinel.internal/v1/status"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("body = %q, want %q in it", body, want)
		}
	}
	if n := len(e.up.requests()); n != 0 {
		t.Errorf("upstream saw %d requests, want none", n)
	}
	rec := e.log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindHTTP })
	if rec.Verdict != audit.Ask || rec.Approval != "ap-1" || rec.Operation != "pulls.merge" || rec.Target != "owner=o repo=r" || rec.Status != 403 {
		t.Errorf("record = %+v", rec)
	}
}

func TestARequestThatCouldNotBeDecidedIsRefusedAsTheGatesFailure(t *testing.T) {
	e := newEnv(t, 1)
	e.mu.Lock()
	e.decider = deciderFunc(func(context.Context, decide.Request) decide.Decision {
		return decide.Decision{Verdict: audit.Deny, Reason: "the ledger could not be read", Error: "disk I/O error"}
	})
	e.mu.Unlock()
	resp, err := e.client().Get("https://api.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get(gate.MarkHeader) != gate.MarkError {
		t.Errorf("response = %d with mark %q, want the gate's 503", resp.StatusCode, resp.Header.Get(gate.MarkHeader))
	}
	rec := e.log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindHTTP })
	if rec.Verdict != audit.Deny || rec.Error != "disk I/O error" {
		t.Errorf("record = %+v", rec)
	}
}

func TestARequestLetThroughOnAGrantIsRecordedWithTheGrant(t *testing.T) {
	e := newEnv(t, 1)
	e.mu.Lock()
	e.decider = deciderFunc(func(context.Context, decide.Request) decide.Decision {
		return decide.Decision{Verdict: audit.Allow, Reason: "granted", Operation: "pulls.merge", Target: "owner=o repo=r", Grant: "gr-1"}
	})
	e.mu.Unlock()
	resp, err := e.client().Get("https://api.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	rec := e.log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindHTTP })
	if rec.Verdict != audit.Allow || rec.Grant != "gr-1" || rec.Operation != "pulls.merge" || rec.Status != 201 {
		t.Errorf("record = %+v", rec)
	}
}

func TestTheDeciderIsGivenTheFactsOfTheRequest(t *testing.T) {
	e := newEnv(t, 1)
	var got decide.Request
	e.mu.Lock()
	e.decider = deciderFunc(func(_ context.Context, r decide.Request) decide.Decision {
		got = r
		return decide.Decision{Verdict: audit.Deny, Reason: "custom"}
	})
	e.mu.Unlock()
	resp, err := e.client().Post("https://api.example.com/p?q=1", "text/plain", strings.NewReader("abc"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got.Source != "workspace" || got.Destination.Name != "api.example.com" || got.Port != 443 ||
		got.Method != "POST" || got.Path != "/p" || got.Query != "q=1" || string(got.Body) != "abc" || !got.BodyComplete ||
		got.BodySummary == nil || got.BodySummary.Text != "abc" || len(got.Settings.Durations) == 0 {
		t.Errorf("Decider got %+v", got)
	}
	rec := e.log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindHTTP })
	if rec.Reason != "custom" {
		t.Errorf("record's reason = %q, want the Decider's", rec.Reason)
	}
}

func TestARequestThatCannotBeRecordedDoesNotGoOut(t *testing.T) {
	e := newEnv(t, 1)
	e.log.mu.Lock()
	e.log.fail = true
	e.log.mu.Unlock()
	resp, err := e.client().Get("https://api.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get(gate.MarkHeader) == "" {
		t.Errorf("response = %d with mark %q, want the gate's 503", resp.StatusCode, resp.Header.Get(gate.MarkHeader))
	}
	if n := len(e.up.requests()); n != 0 {
		t.Errorf("upstream saw %d requests, want none", n)
	}
}

func TestARefusalFromAuthdIsAnsweredByTheGateAndRecordedWithItsReason(t *testing.T) {
	for name, tc := range map[string]struct {
		err      *authdclient.Error
		inRecord string
	}{
		"refused": {&authdclient.Error{Reason: authdclient.ReasonSurrogateMismatch, Message: "the surrogate is not registered for this upstream"}, "authd refused the request"},
		"failed":  {&authdclient.Error{Reason: authdclient.ReasonUpstreamUnreachable, Message: "the upstream could not be reached"}, "authd could not get an answer from the upstream"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, 1)
			e.up.mu.Lock()
			e.up.err = tc.err
			e.up.mu.Unlock()
			resp, err := e.client().Get("https://api.example.com/")
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusBadGateway || resp.Header.Get(gate.MarkHeader) != gate.MarkError {
				t.Errorf("response = %d with mark %q, want the gate's 502", resp.StatusCode, resp.Header.Get(gate.MarkHeader))
			}
			if !strings.Contains(string(body), string(tc.err.Reason)) || !strings.Contains(string(body), tc.err.Message) {
				t.Errorf("body = %q, want authd's reason and message", body)
			}
			rec := e.log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindHTTP })
			if rec.AuthdReason != string(tc.err.Reason) || !strings.Contains(rec.Error, tc.inRecord) || !strings.Contains(rec.Error, tc.err.Message) {
				t.Errorf("record = authdReason %q, error %q", rec.AuthdReason, rec.Error)
			}
		})
	}
}

func TestAnAuthdThatCannotBeReachedIsAnsweredByTheGateAndRecorded(t *testing.T) {
	e := newEnv(t, 1)
	e.up.mu.Lock()
	e.up.err = errors.New("dial unix /run/authd.sock: connect: no such file or directory")
	e.up.mu.Unlock()
	resp, err := e.client().Get("https://api.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || resp.Header.Get(gate.MarkHeader) != gate.MarkError {
		t.Errorf("response = %d with mark %q, want the gate's 502", resp.StatusCode, resp.Header.Get(gate.MarkHeader))
	}
	if !strings.Contains(string(body), "authd could not be reached") {
		t.Errorf("body = %q", body)
	}
	rec := e.log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindHTTP })
	if rec.AuthdReason != "" || !strings.Contains(rec.Error, "authd could not be reached") || !strings.Contains(rec.Error, "no such file") {
		t.Errorf("record = authdReason %q, error %q", rec.AuthdReason, rec.Error)
	}
}

func TestTheAnswerIsStreamedAsItComes(t *testing.T) {
	e := newEnv(t, 1)
	release := make(chan struct{})
	e.setUpstream(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "first line\n")
		w.(http.Flusher).Flush()
		<-release
		_, _ = io.WriteString(w, "second line\n")
	})
	resp, err := e.client().Get("https://api.example.com/logs?follow=true")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	close(release)
	if err != nil || line != "first line\n" {
		t.Fatalf("first line = %q, %v", line, err)
	}
}

func TestAHostThatIsNotTheSNIIsRefused(t *testing.T) {
	e := newEnv(t, 1)
	req, _ := http.NewRequest("GET", "https://api.example.com/", nil)
	req.Host = "closed.example.com"
	resp, err := e.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get(gate.MarkHeader) == "" {
		t.Errorf("response = %d, want the gate's 403", resp.StatusCode)
	}
	if n := len(e.up.requests()); n != 0 {
		t.Errorf("upstream saw %d requests", n)
	}
	rec := e.log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindHTTP })
	if rec.Verdict != audit.Deny || !strings.Contains(rec.Reason, "Host") {
		t.Errorf("record = %+v", rec)
	}
}

func TestAnUpgradeIsRefused(t *testing.T) {
	e := newEnv(t, 1)
	req, _ := http.NewRequest("GET", "https://api.example.com/ws", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	resp, err := e.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented || resp.Header.Get(gate.MarkHeader) == "" {
		t.Errorf("response = %d, want the gate's 501", resp.StatusCode)
	}
	if n := len(e.up.requests()); n != 0 {
		t.Errorf("upstream saw %d requests", n)
	}
}

func TestANameThatIsNotOpenedDoesNotGetPastTLS(t *testing.T) {
	for _, name := range []string{"blocked.example.com", "unknown.example.com"} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, 1)
			_, err := e.client().Get("https://" + name + "/")
			if err == nil {
				t.Fatal("the request got through")
			}
			rec := e.log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindConnection })
			if rec.Name != name || rec.Verdict != audit.Deny || rec.Address != "192.0.2.10:443" {
				t.Errorf("record = %+v", rec)
			}
		})
	}
}

func TestAnOpenNameOnAPortItIsNotOpenedOnIsRefused(t *testing.T) {
	e := newEnv(t, 1)
	e.setOrigDst("192.0.2.10:8443")
	if _, err := e.client().Get("https://api.example.com:8443/"); err == nil {
		t.Fatal("the request got through")
	}
	rec := e.log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindConnection })
	if rec.Verdict != audit.Deny || rec.Address != "192.0.2.10:8443" {
		t.Errorf("record = %+v", rec)
	}
}

func TestTLSWithoutANameIsRefused(t *testing.T) {
	e := newEnv(t, 1)
	conn, err := tls.Dial("tcp", e.addr, &tls.Config{InsecureSkipVerify: true}) // a client that sends no SNI
	if err == nil {
		_ = conn.Close()
		t.Fatal("the handshake succeeded")
	}
	rec := e.log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindConnection })
	if rec.Verdict != audit.Deny || !strings.Contains(rec.Reason, "SNI") {
		t.Errorf("record = %+v", rec)
	}
}

func TestPlainHTTPIsAnsweredByTheGateAndRecorded(t *testing.T) {
	e := newEnv(t, 1)
	e.setOrigDst("192.0.2.10:80")
	resp, err := e.client().Get("http://api.example.com/plain")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get(gate.MarkHeader) == "" {
		t.Errorf("response = %d, want the gate's 403", resp.StatusCode)
	}
	rec := e.log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindConnection })
	if rec.Name != "api.example.com" || rec.Method != "GET" || rec.Path != "/plain" || rec.Verdict != audit.Deny {
		t.Errorf("record = %+v", rec)
	}
	if n := len(e.up.requests()); n != 0 {
		t.Errorf("upstream saw %d requests", n)
	}
}

func TestPlainHTTPToTheGatesOwnAddressReachesTheWorkspacesDoor(t *testing.T) {
	e := newEnv(t, 1)
	e.setOrigDst("192.0.2.53:80")
	c := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, e.addr)
		},
	}, Timeout: 5 * time.Second}
	for i := 0; i < 2; i++ {
		resp, err := c.Get("http://sentinel.internal/v1/status")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 || string(body) != "the agent door: GET /v1/status" {
			t.Errorf("response = %d %q", resp.StatusCode, body)
		}
	}
	if n := len(e.up.requests()); n != 0 {
		t.Errorf("upstream saw %d requests", n)
	}
}

func TestTheGatesOwnAddressOnAnotherPortIsNotTheDoor(t *testing.T) {
	e := newEnv(t, 1)
	e.setOrigDst("192.0.2.53:8080")
	c := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, e.addr)
		},
	}, Timeout: 5 * time.Second}
	resp, err := c.Get("http://sentinel.internal:8080/v1/status")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get(gate.MarkHeader) != gate.MarkDeny {
		t.Errorf("response = %d, want the gate's refusal of plain HTTP", resp.StatusCode)
	}
}

func TestSomethingThatIsNeitherTLSNorHTTPIsCutOffAndRecorded(t *testing.T) {
	e := newEnv(t, 1)
	e.setOrigDst("192.0.2.10:25")
	conn, err := net.Dial("tcp", e.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = conn.Write([]byte("\x00\x01\x02 not a protocol\r\n\r\n"))
	rec := e.log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindConnection })
	if rec.Verdict != audit.Deny || rec.Address != "192.0.2.10:25" {
		t.Errorf("record = %+v", rec)
	}
}

func TestAConnectionThatSaysNothingIsCutOffAndRecorded(t *testing.T) {
	e := newEnv(t, 1)
	e.setOrigDst("192.0.2.10:22")
	conn, err := net.Dial("tcp", e.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	rec := e.log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindConnection })
	if rec.Verdict != audit.Deny {
		t.Errorf("record = %+v", rec)
	}
}

func TestAConnectionWithoutAnOriginalDestinationIsCutOffAndRecorded(t *testing.T) {
	e := newEnv(t, 1)
	e.setOrigDst("")
	conn, err := net.Dial("tcp", e.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	rec := e.log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindConnection })
	if rec.Verdict != audit.Deny || rec.Error == "" {
		t.Errorf("record = %+v", rec)
	}
}

func echoServer(t *testing.T) *net.TCPAddr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr)
}

func TestAPassthroughAddressIsConnectedStraightAndMeasured(t *testing.T) {
	echo := echoServer(t)
	e := newEnv(t, echo.Port)
	e.setOrigDst(echo.String())
	conn, err := net.Dial("tcp", e.addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("echo = %q, %v", buf, err)
	}
	_ = conn.(*net.TCPConn).CloseWrite()
	_, _ = io.Copy(io.Discard, conn)
	_ = conn.Close()

	rec := e.log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindPassthrough })
	if rec.Address != echo.String() || rec.Verdict != audit.Allow || rec.BytesUp != 5 || rec.BytesDown != 5 || rec.Treatment != "passthrough" {
		t.Errorf("record = %+v", rec)
	}
}

func TestAnIPv6PassthroughAddressIsConnectedStraightAndRecordedWithItsAddress(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback here: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	echo := ln.Addr().(*net.TCPAddr)
	e := newEnv(t, echo.Port)
	e.setOrigDst(echo.String())
	conn, err := net.Dial("tcp", e.addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("echo = %q, %v", buf, err)
	}
	_ = conn.(*net.TCPConn).CloseWrite()
	_, _ = io.Copy(io.Discard, conn)
	_ = conn.Close()

	rec := e.log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindPassthrough })
	if rec.Address != fmt.Sprintf("[::1]:%d", echo.Port) || rec.Verdict != audit.Allow || rec.BytesUp != 5 || rec.BytesDown != 5 {
		t.Errorf("record = %+v", rec)
	}
}

func TestAPassthroughThatCannotBeRecordedIsNotConnected(t *testing.T) {
	echo := echoServer(t)
	e := newEnv(t, echo.Port)
	e.setOrigDst(echo.String())
	e.log.mu.Lock()
	e.log.fail = true
	e.log.mu.Unlock()
	conn, err := net.Dial("tcp", e.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write([]byte("hello"))
	if n, err := conn.Read(make([]byte, 5)); err == nil {
		t.Errorf("read %d bytes through a passthrough that was not recorded", n)
	}
}

// has reports whether a finished record satisfies ok now.
func (m *memLog) has(ok func(*audit.Record) bool) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.records {
		if r.Finished && ok(r) {
			return true
		}
	}
	return false
}
