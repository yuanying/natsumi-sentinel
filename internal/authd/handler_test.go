package authd_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/authd"
	"github.com/yuanying/natsumi-sentinel/internal/authdclient"
	"github.com/yuanying/natsumi-sentinel/internal/peercred"
)

// A second credential, registered for other.example.com only.
const (
	otherSurrogate = "surrogate-for-other-0123456789"
	otherKey       = "real-other-key-for-the-test-only"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// harness runs a fake upstream (TLS, certificate for example.com and
// *.example.com), and authd in front of it on a Unix socket, with the gate's
// transport to talk to it.
type harness struct {
	t        *testing.T
	upstream *httptest.Server
	port     string
	keyPath  string
	tr       *authdclient.Transport
	logs     *syncBuffer

	mu      sync.Mutex
	handle  http.HandlerFunc
	reached int
	dialed  []string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, logs: &syncBuffer{}}
	h.handle = func(w http.ResponseWriter, r *http.Request) {}
	h.upstream = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		h.reached++
		handle := h.handle
		h.mu.Unlock()
		handle(w, r)
	}))
	t.Cleanup(h.upstream.Close)
	_, h.port, _ = net.SplitHostPort(h.upstream.Listener.Addr().String())

	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ca := write("ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.upstream.Certificate().Raw})))
	h.keyPath = write("key", testKey+"\n")
	otherKeyPath := write("other-key", otherKey)
	cfgPath := write("authd.yaml", fmt.Sprintf(`upstreams:
  - name: api.example.com
    ports: [%[1]s]
    ca_file: %[2]s
  - name: other.example.com
    ports: [%[1]s]
    ca_file: %[2]s
  - name: untrusted.example.com
    ports: [%[1]s]
  - name: down.example.com
    ports: [%[1]s]
    ca_file: %[2]s
credentials:
  - surrogate: %[3]s
    key_file: %[4]s
    upstreams: [api.example.com, down.example.com]
    places:
      - type: bearer
      - type: bearer
        scheme: token
      - type: basic
      - type: header
        name: X-Api-Key
      - type: query
        name: api_key
  - surrogate: %[5]s
    key_file: %[6]s
    upstreams: [other.example.com]
    places:
      - type: header
        name: X-Other-Key
`, h.port, ca, testSurrogate, h.keyPath, otherSurrogate, otherKeyPath))

	cfg, err := authd.LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	upstreamAddr := h.upstream.Listener.Addr().String()
	handler, err := authd.NewHandler(cfg, authd.Options{
		Logger: slog.New(slog.NewTextHandler(h.logs, nil)),
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			h.mu.Lock()
			h.dialed = append(h.dialed, addr)
			h.mu.Unlock()
			if strings.HasPrefix(addr, "down.example.com:") {
				return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("connection refused")}
			}
			var d net.Dialer
			return d.DialContext(ctx, network, upstreamAddr)
		},
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	sockDir, err := os.MkdirTemp("", "authd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "authd.sock")
	l, err := peercred.Listen(sock, os.Getuid(), nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })

	h.tr = authdclient.NewTransport(sock)
	t.Cleanup(h.tr.CloseIdleConnections)
	return h
}

func (h *harness) setHandler(f http.HandlerFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.handle = f
}

func (h *harness) reachedCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.reached
}

func (h *harness) dialedAddrs() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.dialed...)
}

func (h *harness) url(name, pathAndQuery string) string {
	return "https://" + net.JoinHostPort(name, h.port) + pathAndQuery
}

func (h *harness) request(method, name, pathAndQuery string, body io.Reader) *http.Request {
	h.t.Helper()
	req, err := http.NewRequest(method, h.url(name, pathAndQuery), body)
	if err != nil {
		h.t.Fatal(err)
	}
	return req
}

func (h *harness) send(req *http.Request) (*http.Response, error) {
	resp, err := h.tr.RoundTrip(req)
	if err == nil {
		h.t.Cleanup(func() { _ = resp.Body.Close() })
	}
	return resp, err
}

func (h *harness) mustSend(req *http.Request) *http.Response {
	h.t.Helper()
	resp, err := h.send(req)
	if err != nil {
		h.t.Fatalf("RoundTrip: %v", err)
	}
	return resp
}

// refusal sends req and wants authd's own error with the given reason.
func (h *harness) refusal(req *http.Request, want authdclient.Reason) {
	h.t.Helper()
	_ = h.authdError(req, want)
}

// authdError is refusal that also hands back the error.
func (h *harness) authdError(req *http.Request, want authdclient.Reason) *authdclient.Error {
	h.t.Helper()
	resp, err := h.send(req)
	if err == nil {
		h.t.Fatalf("RoundTrip gave status %d, want authd's %q", resp.StatusCode, want)
	}
	var aerr *authdclient.Error
	if !errors.As(err, &aerr) {
		h.t.Fatalf("error %v is not authd's", err)
	}
	if aerr.Reason != want {
		h.t.Fatalf("reason = %q (%s), want %q", aerr.Reason, aerr.Message, want)
	}
	h.noSecretIn(aerr.Message)
	h.noSecretIn(h.logs.String())
	return aerr
}

func (h *harness) noSecretIn(s string) {
	h.t.Helper()
	for _, v := range []string{testSurrogate, testKey, otherSurrogate, otherKey} {
		if strings.Contains(s, v) {
			h.t.Errorf("%q holds a surrogate or a key", s)
		}
	}
}

// captured is what the fake upstream saw of one request.
type captured struct {
	host, sni, rawQuery, body string
	header                    http.Header
	user, pass                string
	basic                     bool
}

func (h *harness) capture() <-chan captured {
	ch := make(chan captured, 1)
	h.setHandler(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		c := captured{host: r.Host, rawQuery: r.URL.RawQuery, body: string(b), header: r.Header.Clone()}
		if r.TLS != nil {
			c.sni = r.TLS.ServerName
		}
		c.user, c.pass, c.basic = r.BasicAuth()
		ch <- c
	})
	return ch
}

func TestTheUpstreamIsReachedByTheNameTheGateGaveAndItsCertificateIsChecked(t *testing.T) {
	h := newHarness(t)
	got := h.capture()
	h.mustSend(h.request(http.MethodGet, "api.example.com", "/", nil))
	c := <-got
	if c.sni != "api.example.com" {
		t.Errorf("SNI = %q, want api.example.com", c.sni)
	}
	if want := "api.example.com:" + h.port; c.host != want {
		t.Errorf("Host = %q, want %q", c.host, want)
	}
	if d := h.dialedAddrs(); len(d) != 1 || d[0] != "api.example.com:"+h.port {
		t.Errorf("dialed %v, want the name and port the gate gave", d)
	}
	if v := c.header.Get("X-Forwarded-For"); v != "" {
		t.Errorf("X-Forwarded-For = %q, want none", v)
	}
}

func TestABearerSurrogateIsSwappedForTheRealKey(t *testing.T) {
	h := newHarness(t)
	got := h.capture()
	req := h.request(http.MethodGet, "api.example.com", "/user", nil)
	req.Header.Set("Authorization", "Bearer "+testSurrogate)
	h.mustSend(req)
	if a := (<-got).header.Get("Authorization"); a != "Bearer "+testKey {
		t.Errorf("Authorization = %q, want the real key", a)
	}
}

func TestABearerPlaceWithItsOwnSchemeSwapsUnderThatScheme(t *testing.T) {
	h := newHarness(t)
	got := h.capture()
	req := h.request(http.MethodGet, "api.example.com", "/user", nil)
	req.Header.Set("Authorization", "token "+testSurrogate)
	h.mustSend(req)
	if a := (<-got).header.Get("Authorization"); a != "token "+testKey {
		t.Errorf("Authorization = %q, want the real key under the token scheme", a)
	}
}

func TestABasicPasswordSurrogateIsSwappedAndTheUserIsKept(t *testing.T) {
	h := newHarness(t)
	got := h.capture()
	req := h.request(http.MethodGet, "api.example.com", "/repo.git/info/refs", nil)
	req.SetBasicAuth("x-access-token", testSurrogate)
	h.mustSend(req)
	c := <-got
	if !c.basic || c.user != "x-access-token" || c.pass != testKey {
		t.Errorf("basic auth = %v %q %q, want the same user and the real key", c.basic, c.user, c.pass)
	}
}

func TestAHeaderSurrogateIsSwapped(t *testing.T) {
	h := newHarness(t)
	got := h.capture()
	req := h.request(http.MethodGet, "api.example.com", "/", nil)
	req.Header.Set("X-Api-Key", testSurrogate)
	h.mustSend(req)
	if v := (<-got).header.Get("X-Api-Key"); v != testKey {
		t.Errorf("X-Api-Key = %q, want the real key", v)
	}
}

func TestAQuerySurrogateIsSwappedAndTheRestOfTheQueryIsKeptAsItWas(t *testing.T) {
	h := newHarness(t)
	got := h.capture()
	h.mustSend(h.request(http.MethodGet, "api.example.com", "/v1?z=1&api_key="+testSurrogate+"&a=%2F+x", nil))
	if q, want := (<-got).rawQuery, "z=1&api_key="+url.QueryEscape(testKey)+"&a=%2F+x"; q != want {
		t.Errorf("query = %q, want %q", q, want)
	}
}

func TestTheBodyIsSentUntouchedEvenWhenItHoldsASurrogate(t *testing.T) {
	h := newHarness(t)
	got := h.capture()
	body := `{"token":"` + testSurrogate + `"}`
	req := h.request(http.MethodPost, "api.example.com", "/", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testSurrogate)
	h.mustSend(req)
	if b := (<-got).body; b != body {
		t.Errorf("body = %q, want it as it was sent", b)
	}
}

func TestARequestWithoutASurrogateIsSentWithoutAKey(t *testing.T) {
	h := newHarness(t)
	got := h.capture()
	h.mustSend(h.request(http.MethodGet, "api.example.com", "/", nil))
	if a := (<-got).header.Get("Authorization"); a != "" {
		t.Errorf("Authorization = %q, want none", a)
	}

	got = h.capture()
	req := h.request(http.MethodGet, "api.example.com", "/", nil)
	req.Header.Set("Authorization", "Bearer something-that-is-not-a-surrogate")
	h.mustSend(req)
	if a := (<-got).header.Get("Authorization"); a != "Bearer something-that-is-not-a-surrogate" {
		t.Errorf("Authorization = %q, want it as it was sent", a)
	}
}

func TestASurrogateForAnotherUpstreamIsRefusedAndNothingIsSent(t *testing.T) {
	h := newHarness(t)
	req := h.request(http.MethodGet, "other.example.com", "/", nil)
	req.Header.Set("Authorization", "Bearer "+testSurrogate)
	h.refusal(req, authdclient.ReasonSurrogateMismatch)
	if n := h.reachedCount(); n != 0 {
		t.Errorf("the upstream was reached %d times", n)
	}
}

func TestASurrogateInAPlaceNotRegisteredForItIsRefused(t *testing.T) {
	h := newHarness(t)
	req := h.request(http.MethodGet, "other.example.com", "/", nil)
	req.Header.Set("Authorization", "Bearer "+otherSurrogate)
	h.refusal(req, authdclient.ReasonSurrogateMismatch)

	req = h.request(http.MethodGet, "api.example.com", "/", nil)
	req.Header.Set("X-Other-Key", testSurrogate)
	h.refusal(req, authdclient.ReasonSurrogateMismatch)
	if n := h.reachedCount(); n != 0 {
		t.Errorf("the upstream was reached %d times", n)
	}
}

func TestAnUnregisteredNameOrPortIsRefusedAndNothingIsSent(t *testing.T) {
	h := newHarness(t)
	h.refusal(h.request(http.MethodGet, "nowhere.example.com", "/", nil), authdclient.ReasonUpstreamNotRegistered)

	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com:1/", nil)
	h.refusal(req, authdclient.ReasonUpstreamNotRegistered)
	if n, d := h.reachedCount(), h.dialedAddrs(); n != 0 || len(d) != 0 {
		t.Errorf("the upstream was reached %d times, dialed %v", n, d)
	}
}

func TestAKeyThatCannotBeReadIsRefusedAndNothingIsSent(t *testing.T) {
	h := newHarness(t)
	if err := os.Remove(h.keyPath); err != nil {
		t.Fatal(err)
	}
	req := h.request(http.MethodGet, "api.example.com", "/", nil)
	req.Header.Set("Authorization", "Bearer "+testSurrogate)
	h.refusal(req, authdclient.ReasonCredentialUnavailable)
	if n := h.reachedCount(); n != 0 {
		t.Errorf("the upstream was reached %d times", n)
	}
}

func TestAKeyFileThatChangesIsReadAgain(t *testing.T) {
	h := newHarness(t)
	const rotated = "rotated-real-key-for-the-test"
	// kubelet replaces a mounted file by swapping a symlink; a rename gives
	// the same: a new file at the same path.
	tmp := h.keyPath + ".new"
	if err := os.WriteFile(tmp, []byte(rotated+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, h.keyPath); err != nil {
		t.Fatal(err)
	}
	got := h.capture()
	req := h.request(http.MethodGet, "api.example.com", "/", nil)
	req.Header.Set("Authorization", "Bearer "+testSurrogate)
	h.mustSend(req)
	if a := (<-got).header.Get("Authorization"); a != "Bearer "+rotated {
		t.Errorf("Authorization = %q, want the new key", a)
	}
}

func TestARedirectIsNotFollowed(t *testing.T) {
	h := newHarness(t)
	h.setHandler(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.example.com/", http.StatusFound)
	})
	req := h.request(http.MethodGet, "api.example.com", "/", nil)
	req.Header.Set("Authorization", "Bearer "+testSurrogate)
	resp := h.mustSend(req)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "https://elsewhere.example.com/" {
		t.Errorf("got %d to %q, want the redirect handed back", resp.StatusCode, resp.Header.Get("Location"))
	}
	if n, d := h.reachedCount(), h.dialedAddrs(); n != 1 || len(d) != 1 {
		t.Errorf("reached %d times, dialed %v, want one request", n, d)
	}
}

func TestTheResponseIsStreamedAsItArrives(t *testing.T) {
	h := newHarness(t)
	release := make(chan struct{})
	defer close(release)
	h.setHandler(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "first\n")
		w.(http.Flusher).Flush()
		<-release
		_, _ = io.WriteString(w, "second\n")
	})
	resp := h.mustSend(h.request(http.MethodGet, "api.example.com", "/watch", nil))
	line := make(chan string, 1)
	go func() {
		s, _ := bufio.NewReader(resp.Body).ReadString('\n')
		line <- s
	}()
	select {
	case s := <-line:
		if s != "first\n" {
			t.Errorf("first line = %q", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the first line did not arrive before the response ended")
	}
}

func TestTheRequestBodyIsStreamedAsItIsWritten(t *testing.T) {
	h := newHarness(t)
	firstLine := make(chan string, 1)
	h.setHandler(func(w http.ResponseWriter, r *http.Request) {
		s, _ := bufio.NewReader(r.Body).ReadString('\n')
		firstLine <- s
		_, _ = io.Copy(io.Discard, r.Body)
	})
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	req := h.request(http.MethodPost, "api.example.com", "/upload", pr)
	go func() { _, _ = h.send(req) }()
	if _, err := io.WriteString(pw, "first\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-firstLine:
		if s != "first\n" {
			t.Errorf("first line = %q", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the first line did not reach the upstream before the body ended")
	}
}

func TestAnUpgradeIsPassedThroughBothWays(t *testing.T) {
	h := newHarness(t)
	h.setHandler(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "test-echo" {
			http.Error(w, "no upgrade", http.StatusBadRequest)
			return
		}
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test-echo\r\n\r\n")
		_ = rw.Flush()
		line, err := rw.ReadString('\n')
		if err != nil {
			return
		}
		_, _ = rw.WriteString(line)
		_ = rw.Flush()
	})
	req := h.request(http.MethodGet, "api.example.com", "/stream", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "test-echo")
	resp := h.mustSend(req)
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	rwc, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		t.Fatalf("the body of a 101 is %T, not writable", resp.Body)
	}
	if _, err := io.WriteString(rwc, "ping\n"); err != nil {
		t.Fatal(err)
	}
	s, err := bufio.NewReader(rwc).ReadString('\n')
	if err != nil || s != "ping\n" {
		t.Errorf("echo = %q, %v", s, err)
	}
}

func TestAnUpstreamWhoseCertificateDoesNotVerifyIsAFailure(t *testing.T) {
	h := newHarness(t)
	req := h.request(http.MethodGet, "untrusted.example.com", "/", nil)
	aerr := h.authdError(req, authdclient.ReasonUpstreamCertificate)
	if aerr.Refused() {
		t.Error("a certificate failure counted as a refusal")
	}
	if n := h.reachedCount(); n != 0 {
		t.Errorf("the upstream handled %d requests", n)
	}
}

func TestAnUpstreamThatCannotBeReachedIsAFailureAndTheQueryKeyIsNotShown(t *testing.T) {
	h := newHarness(t)
	// The key is in the URL by the time authd dials; the failure must not
	// carry the URL.
	req := h.request(http.MethodGet, "down.example.com", "/?api_key="+testSurrogate, nil)
	h.refusal(req, authdclient.ReasonUpstreamUnreachable)
}

func TestAnUpstreamsOwnAuthdErrorHeaderIsRemoved(t *testing.T) {
	h := newHarness(t)
	h.setHandler(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(authdclient.ErrorHeader, string(authdclient.ReasonSurrogateMismatch))
		w.WriteHeader(http.StatusForbidden)
	})
	resp := h.mustSend(h.request(http.MethodGet, "api.example.com", "/", nil))
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want the upstream's 403", resp.StatusCode)
	}
	if v := resp.Header.Get(authdclient.ErrorHeader); v != "" {
		t.Errorf("%s = %q, want it removed", authdclient.ErrorHeader, v)
	}
}

func TestARequestWithoutAUsableHostIsABadRequest(t *testing.T) {
	cfgFiles := newFiles(t)
	cfg, err := authd.LoadConfig(cfgFiles.config(t))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := authd.NewHandler(cfg, authd.Options{Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"", "api.example.com:port", "api.example.com:" + strconv.Itoa(1<<20)} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if got := rec.Header().Get(authdclient.ErrorHeader); got != string(authdclient.ReasonBadRequest) {
			t.Errorf("Host %q: %s = %q, want %q", host, authdclient.ErrorHeader, got, authdclient.ReasonBadRequest)
		}
	}
}

func TestASurrogateOutsideEveryRegisteredPlaceIsNotSentOn(t *testing.T) {
	h := newHarness(t)
	req := h.request(http.MethodGet, "api.example.com", "/", nil)
	req.Header.Set("X-Something-Else", "prefix "+testSurrogate)
	h.refusal(req, authdclient.ReasonSurrogateMismatch)

	h.refusal(h.request(http.MethodGet, "api.example.com", "/?other="+testSurrogate, nil), authdclient.ReasonSurrogateMismatch)

	req = h.request(http.MethodGet, "api.example.com", "/", nil)
	req.SetBasicAuth(testSurrogate, "not-a-surrogate")
	h.refusal(req, authdclient.ReasonSurrogateMismatch)
	if n := h.reachedCount(); n != 0 {
		t.Errorf("the upstream was reached %d times", n)
	}
}
