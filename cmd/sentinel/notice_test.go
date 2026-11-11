package main

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeAlertmanager stands for authd's side of the sender, answering the
// requests to Alertmanager's name.
type fakeAlertmanager struct {
	mu     sync.Mutex
	posts  []string
	posted chan struct{}
}

func withAlertmanager(t *testing.T) *fakeAlertmanager {
	t.Helper()
	am := &fakeAlertmanager{posted: make(chan struct{}, 100)}
	old := newUpstream
	newUpstream = func() (http.RoundTripper, error) {
		return tripper(func(r *http.Request) (*http.Response, error) {
			b, _ := io.ReadAll(r.Body)
			if r.URL.Host == "alerts.example.com" && r.URL.Path == "/api/v2/alerts" && r.Method == http.MethodPost {
				am.mu.Lock()
				am.posts = append(am.posts, string(b))
				am.mu.Unlock()
				am.posted <- struct{}{}
			}
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: http.Header{}}, nil
		}), nil
	}
	t.Cleanup(func() { newUpstream = old })
	return am
}

func (am *fakeAlertmanager) wait(t *testing.T) []map[string]any {
	t.Helper()
	select {
	case <-am.posted:
	case <-time.After(5 * time.Second):
		t.Fatal("nothing was posted to Alertmanager")
	}
	am.mu.Lock()
	defer am.mu.Unlock()
	var alerts []map[string]any
	if err := json.Unmarshal([]byte(am.posts[len(am.posts)-1]), &alerts); err != nil {
		t.Fatal(err)
	}
	return alerts
}

type tripper func(*http.Request) (*http.Response, error)

func (f tripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestANameRefusedForTheFirstTimeIsToldToAlertmanagerThroughTheSender(t *testing.T) {
	am := withAlertmanager(t)
	s := newSetup(t)
	r := startGate(t, s, []string{"workspace/dns-udp"},
		"-alertmanager-url", "https://alerts.example.com",
		"-alert-label", "instance=example")
	r.query("made-up.example.net")

	alerts := am.wait(t)
	if len(alerts) != 1 {
		t.Fatalf("posted %d alerts, want 1", len(alerts))
	}
	labels, _ := alerts[0]["labels"].(map[string]any)
	for k, v := range map[string]string{"alertname": "SentinelFirstSeen", "pair": "denied-name", "key": "made-up.example.net", "instance": "example", "source": "workspace"} {
		if labels[k] != v {
			t.Errorf("label %s = %v, want %s", k, labels[k], v)
		}
	}

	// Seen once, it is not told again.
	r.query("made-up.example.net")
	select {
	case <-am.posted:
		t.Error("the same name was told twice")
	case <-time.After(200 * time.Millisecond):
	}
	if code := r.stop(); code != 0 {
		t.Fatalf("run = %d; stderr: %s", code, r.stderr.String())
	}

	db, err := sql.Open("sqlite", s.db)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var gate, seen int
	if err := db.QueryRow(`SELECT count(*) FROM records WHERE kind = 'gate' AND name = 'alerts.example.com' AND status = 200`).Scan(&gate); err != nil || gate != 1 {
		t.Errorf("records of the notice sent = %d, %v; want 1", gate, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM seen WHERE pair = 'denied-name' AND key = 'made-up.example.net'`).Scan(&seen); err != nil || seen != 1 {
		t.Errorf("pairs kept = %d, %v; want 1", seen, err)
	}
}

func TestWithoutAlertmanagerTheNoticesAreOnlyLogged(t *testing.T) {
	withUpstream(t)
	r := startGate(t, newSetup(t), []string{"workspace/dns-udp"})
	r.query("made-up.example.net")
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(r.stderr.String(), "First seen, a name refused in name resolution: made-up.example.net") {
		if time.Now().After(deadline) {
			t.Fatalf("stderr = %s, want the notice", r.stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestNoticeSettingsThatCannotBeUsedDoNotStopTheGate(t *testing.T) {
	withUpstream(t)
	r := startGate(t, newSetup(t), []string{"workspace/dns-udp", "metrics"},
		"-metrics-listen", "127.0.0.1:0",
		"-alertmanager-url", "http://alerts.example.com",
		"-alert-label", "no-equals-sign",
		"-summary-at", "25:00",
		"-summary-timezone", "Nowhere/Nothing")
	if rc := r.query("made-up.example.net"); rc != 3 {
		t.Errorf("rcode = %v, want NXDOMAIN from a gate that runs", rc)
	}
	if !strings.Contains(r.metrics(), "sentinel_notice_sender_configured 0\n") {
		t.Error("the metrics do not say the notices are not sent")
	}
	stderr := r.stderr.String()
	for _, want := range []string{"Alertmanager", "no-equals-sign", "25:00", "Nowhere/Nothing"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr does not name %q: %s", want, stderr)
		}
	}
}
