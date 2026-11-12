package gate_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
)

func (e *env) tlsDial(t *testing.T, name string) *tls.Conn {
	t.Helper()
	conn, err := tls.Dial("tcp", e.addr, &tls.Config{ServerName: name, RootCAs: e.ca.Pool()})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	return conn
}

func TestAConnectionClosedBeforeAnyRequestIsRecordedButNotAsARefusal(t *testing.T) {
	e := newEnv(t, 1)
	conn := e.tlsDial(t, "api.example.com")
	_ = conn.Close()

	rec := e.log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindConnection })
	if rec.Verdict != audit.Allow || rec.Reason != audit.ReasonConnectionUnused ||
		rec.Name != "api.example.com" || rec.Treatment != "open" || rec.Address != "192.0.2.10:443" {
		t.Errorf("record = %+v, want an open connection nothing was asked on", rec)
	}
	if n := len(e.up.requests()); n != 0 {
		t.Errorf("upstream saw %d requests", n)
	}
}

func TestAConnectionThatSendsSomethingThatIsNotARequestIsStillRefused(t *testing.T) {
	e := newEnv(t, 1)
	conn := e.tlsDial(t, "api.example.com")
	defer func() { _ = conn.Close() }()
	_, _ = io.WriteString(conn, "not a request\r\n\r\n")
	_, _ = io.ReadAll(conn)

	rec := e.log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindConnection })
	if rec.Verdict != audit.Deny || rec.Reason == audit.ReasonConnectionUnused || !strings.Contains(rec.Reason, "no request was read") {
		t.Errorf("record = %+v, want the refusal of what was sent", rec)
	}
}

// Go's net/http client dials for a request, and when a connection it
// already had comes free first, sends the request on that one and keeps
// the new connection idle. Closed idle, it never carried a request.
func TestAConnectionAnHTTPClientDialedAndNeverUsedIsNotARefusal(t *testing.T) {
	e := newEnv(t, 1)
	release := make(chan struct{})
	e.setUpstream(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			<-release
		}
		_, _ = io.WriteString(w, "ok")
	})

	var (
		mu    sync.Mutex
		dials int
	)
	holdDial := make(chan struct{})
	shaken := make(chan struct{})
	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			mu.Lock()
			dials++
			n := dials
			mu.Unlock()
			if n == 2 {
				<-holdDial
				defer close(shaken)
			}
			var d tls.Dialer
			d.Config = &tls.Config{RootCAs: e.ca.Pool(), ServerName: "api.example.com"}
			return d.DialContext(ctx, network, e.addr)
		},
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	get := func(path string) {
		resp, err := c.Get("https://api.example.com" + path)
		if err != nil {
			t.Errorf("GET %s: %v", path, err)
			return
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
	}
	// The first request holds the first connection.
	first := make(chan struct{})
	go func() { defer close(first); get("/slow") }()
	waitUntil(t, func() bool { return len(e.up.requests()) == 1 })
	// The second dials a connection of its own, which is held back until
	// the first connection is free and has taken the second request.
	second := make(chan struct{})
	go func() { defer close(second); get("/fast") }()
	waitUntil(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return dials == 2
	})
	close(release)
	<-first
	<-second
	close(holdDial)
	<-shaken

	// The dialed connection finishes its handshake and waits idle; close
	// it as the tool does when it is done.
	deadline := time.Now().Add(5 * time.Second)
	for !e.log.has(func(r *audit.Record) bool { return r.Kind == audit.KindConnection }) && time.Now().Before(deadline) {
		tr.CloseIdleConnections()
		time.Sleep(20 * time.Millisecond)
	}
	rec := e.log.waitFor(t, func(r *audit.Record) bool { return r.Kind == audit.KindConnection })
	if rec.Verdict != audit.Allow || rec.Reason != audit.ReasonConnectionUnused {
		t.Errorf("record = %+v, want a connection nothing was asked on", rec)
	}
	if e.log.has(func(r *audit.Record) bool { return r.Verdict == audit.Deny }) {
		t.Error("something was recorded as refused")
	}
}

func waitUntil(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
