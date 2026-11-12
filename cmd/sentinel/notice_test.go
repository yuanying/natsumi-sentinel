package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/ledger"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

// fakeAlertmanager stands for authd's side of the sender, answering the
// requests to Alertmanager's name.
type fakeAlertmanager struct {
	mu     sync.Mutex
	posts  []string
	auths  [][]string
	posted chan struct{}
}

func withAlertmanager(t *testing.T) *fakeAlertmanager {
	t.Helper()
	am := &fakeAlertmanager{posted: make(chan struct{}, 100)}
	old := newUpstream
	newUpstream = func(string) http.RoundTripper {
		return tripper(func(r *http.Request) (*http.Response, error) {
			b, _ := io.ReadAll(r.Body)
			if r.URL.Host == "alerts.example.com" && r.URL.Path == "/api/v2/alerts" && r.Method == http.MethodPost {
				am.mu.Lock()
				am.posts = append(am.posts, string(b))
				am.auths = append(am.auths, r.Header.Values("Authorization"))
				am.mu.Unlock()
				am.posted <- struct{}{}
			}
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: http.Header{}}, nil
		})
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

func TestTheOwnersAnswerIsToldToAlertmanagerAndTheApprovalsWaitingAreCounted(t *testing.T) {
	am := withAlertmanager(t)
	s := newSetup(t)
	book, err := ledger.Open(s.ledger, nil)
	if err != nil {
		t.Fatal(err)
	}
	a, _, err := book.Hold(context.Background(), ledger.Facts{
		Source: "workspace", Destination: "api.example.com", Method: "POST", Path: "/markdown",
		Fingerprint: "fp", Exact: true,
	}, routes.ApprovalSettings{Durations: []time.Duration{time.Hour}, Once: 10 * time.Minute, Pending: 24 * time.Hour})
	_ = book.Close()
	if err != nil {
		t.Fatal(err)
	}

	r := startGate(t, s, []string{"workspace/dns-udp", "metrics"},
		"-metrics-listen", "127.0.0.1:0",
		"-alertmanager-url", "https://alerts.example.com")
	if page := r.metrics(); !strings.Contains(page, "sentinel_approvals_pending 1\n") {
		t.Errorf("the metrics do not count the approval waiting:\n%s", page)
	}

	oc := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", s.approvals)
	}}, Timeout: 5 * time.Second}
	resp, err := oc.Post("http://sentinel/v1/approvals/"+a.ID+"/answer", "application/json", strings.NewReader(`{"answer":"allow","choice":"1h"}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("answer = %d", resp.StatusCode)
	}

	alerts := am.wait(t)
	labels, _ := alerts[0]["labels"].(map[string]any)
	for k, v := range map[string]string{"alertname": "SentinelAnswer", "answer": "allowed", "approval": a.ID, "source": "workspace"} {
		if labels[k] != v {
			t.Errorf("label %s = %v, want %s", k, labels[k], v)
		}
	}
	if page := r.metrics(); !strings.Contains(page, "sentinel_approvals_pending 0\n") {
		t.Errorf("the metrics still count the approval answered:\n%s", page)
	}
}

func TestAnAnswerToAPushOfTwoRefsTellsBothOperationsAndNotWhatTheGateLookedUp(t *testing.T) {
	am := withAlertmanager(t)
	s := newSetup(t)
	book, err := ledger.Open(s.ledger, nil)
	if err != nil {
		t.Fatal(err)
	}
	const sha = "1111111111111111111111111111111111111111"
	item := func(ref string) ledger.Facts {
		return ledger.Facts{
			Source: "workspace", Destination: "git.example.com", Method: "POST", Path: "/o/r.git/git-receive-pack",
			Operation:   "github.push.other",
			Params:      []routes.Param{{Name: "owner", Value: "o"}, {Name: "repo", Value: "r"}, {Name: "ref", Value: ref}, {Name: "sha", Value: sha}},
			Target:      []string{"owner", "repo", "ref"},
			Facts:       []routes.Param{{Name: "kind", Value: "update"}, {Name: "fastForward", Value: "unknown"}},
			Body:        &audit.Body{Text: "the commands of the push"},
			Fingerprint: "fp-" + ref, Exact: true,
		}
	}
	a, _, err := book.HoldAll(context.Background(), []ledger.Facts{item("refs/heads/a"), item("refs/heads/b")},
		routes.ApprovalSettings{Durations: []time.Duration{time.Hour}, Once: 10 * time.Minute, Pending: 24 * time.Hour})
	_ = book.Close()
	if err != nil {
		t.Fatal(err)
	}

	r := startGate(t, s, []string{"workspace/dns-udp", "metrics"},
		"-metrics-listen", "127.0.0.1:0",
		"-alertmanager-url", "https://alerts.example.com")
	if page := r.metrics(); !strings.Contains(page, "sentinel_approvals_pending 1\n") {
		t.Errorf("the metrics do not count the approval of two items as one:\n%s", page)
	}
	oc := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", s.approvals)
	}}, Timeout: 5 * time.Second}
	resp, err := oc.Post("http://sentinel/v1/approvals/"+a.ID+"/answer", "application/json", strings.NewReader(`{"answer":"allow","choice":"once"}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("answer = %d", resp.StatusCode)
	}

	alerts := am.wait(t)
	annotations, _ := alerts[0]["annotations"].(map[string]any)
	summary, _ := annotations["summary"].(string)
	description, _ := annotations["description"].(string)
	if !strings.Contains(summary, "github.push.other (owner=o repo=r ref=refs/heads/a) on git.example.com and 1 more") {
		t.Errorf("summary = %q", summary)
	}
	for _, ref := range []string{"refs/heads/a", "refs/heads/b"} {
		if !strings.Contains(description, "github.push.other (owner=o repo=r ref="+ref+") on git.example.com") {
			t.Errorf("description does not tell %s: %q", ref, description)
		}
	}
	for _, s := range []string{sha, "fastForward", "the commands of the push"} {
		if strings.Contains(summary+description, s) {
			t.Errorf("the notice tells %q:\n%s\n%s", s, summary, description)
		}
	}
}

const noticeSurrogate = "surrogate-for-the-notices-0123456789"

func TestTheSurrogateGivenIsPutOnTheNoticesAndKeptOutOfTheLogsAndRecords(t *testing.T) {
	am := withAlertmanager(t)
	s := newSetup(t)
	r := startGate(t, s, []string{"workspace/dns-udp"},
		"-alertmanager-url", "https://alerts.example.com",
		"-alertmanager-surrogate", noticeSurrogate)
	r.query("made-up.example.net")
	am.wait(t)
	if code := r.stop(); code != 0 {
		t.Fatalf("run = %d; stderr: %s", code, r.stderr.String())
	}
	am.mu.Lock()
	auth := am.auths[0]
	am.mu.Unlock()
	if len(auth) != 1 || auth[0] != "Bearer "+noticeSurrogate {
		t.Errorf("Authorization = %q, want the surrogate as a bearer", auth)
	}
	if strings.Contains(r.stderr.String(), noticeSurrogate) {
		t.Errorf("stderr tells the surrogate: %s", r.stderr.String())
	}

	db, err := sql.Open("sqlite", s.db)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM records WHERE kind = 'gate' AND name = 'alerts.example.com'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("records of the notice sent = %d, %v; want 1", n, err)
	}
	// stdout is the copy of every record, each in full.
	if out := r.stdout.String(); !strings.Contains(out, "alerts.example.com") || strings.Contains(out, noticeSurrogate) {
		t.Errorf("the copy of the records = %s, want the notice's record without the surrogate", out)
	}
}

func TestWithoutASurrogateTheNoticesCarryNoAuthorization(t *testing.T) {
	am := withAlertmanager(t)
	r := startGate(t, newSetup(t), []string{"workspace/dns-udp"},
		"-alertmanager-url", "https://alerts.example.com")
	r.query("made-up.example.net")
	am.wait(t)
	am.mu.Lock()
	defer am.mu.Unlock()
	if len(am.auths[0]) != 0 {
		t.Errorf("Authorization = %q, want none", am.auths[0])
	}
}

func TestASurrogateWithoutAnAlertmanagerURLIsNotUsedAndDoesNotStopTheGate(t *testing.T) {
	withUpstream(t)
	r := startGate(t, newSetup(t), []string{"workspace/dns-udp", "metrics"},
		"-metrics-listen", "127.0.0.1:0",
		"-alertmanager-surrogate", noticeSurrogate)
	if rc := r.query("made-up.example.net"); rc != 3 {
		t.Errorf("rcode = %v, want NXDOMAIN from a gate that runs", rc)
	}
	if !strings.Contains(r.metrics(), "sentinel_notice_sender_configured 0\n") {
		t.Error("the metrics do not say the notices are not sent")
	}
	stderr := r.stderr.String()
	if !strings.Contains(stderr, "-alertmanager-surrogate") {
		t.Errorf("stderr does not say the surrogate is not used: %s", stderr)
	}
	if strings.Contains(stderr, noticeSurrogate) {
		t.Errorf("stderr tells the surrogate: %s", stderr)
	}
}

func TestASurrogateThatCannotBeABearerLeavesTheNoticesOnlyLoggedAndIsNotTold(t *testing.T) {
	withAlertmanager(t)
	const bad = "surrogate with spaces 0123456789"
	r := startGate(t, newSetup(t), []string{"workspace/dns-udp", "metrics"},
		"-metrics-listen", "127.0.0.1:0",
		"-alertmanager-url", "https://alerts.example.com",
		"-alertmanager-surrogate", bad)
	if rc := r.query("made-up.example.net"); rc != 3 {
		t.Errorf("rcode = %v, want NXDOMAIN from a gate that runs", rc)
	}
	if !strings.Contains(r.metrics(), "sentinel_notice_sender_configured 0\n") {
		t.Error("the metrics do not say the notices are not sent")
	}
	stderr := r.stderr.String()
	if !strings.Contains(stderr, "-alertmanager-surrogate") || strings.Contains(stderr, bad) {
		t.Errorf("stderr = %s, want it to name the flag and not the value", stderr)
	}
}
