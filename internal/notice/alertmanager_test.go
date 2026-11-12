package notice_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/notice"
)

type tripper func(*http.Request) (*http.Response, error)

func (f tripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// recLog keeps the records the sender writes.
type recLog struct {
	mu      sync.Mutex
	begun   []audit.Record
	done    []audit.Record
	failing error
}

func (l *recLog) Begin(_ context.Context, rec *audit.Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.failing != nil {
		return l.failing
	}
	rec.ID = int64(len(l.begun) + 1)
	l.begun = append(l.begun, *rec)
	return nil
}

func (l *recLog) Finish(_ context.Context, rec *audit.Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.done = append(l.done, *rec)
	return nil
}

type alert struct {
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	StartsAt    time.Time         `json:"startsAt"`
	EndsAt      time.Time         `json:"endsAt"`
}

func TestNoticesArePostedToAlertmanagerThroughTheSenderAndRecorded(t *testing.T) {
	var (
		got  *http.Request
		body []byte
	)
	now := at.Add(time.Hour)
	log := &recLog{}
	am, err := notice.NewAlertmanager(notice.AlertmanagerConfig{
		URL: "https://alerts.example.com/",
		Transport: tripper(func(r *http.Request) (*http.Response, error) {
			got = r
			body, _ = io.ReadAll(r.Body)
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
		}),
		Log:    log,
		Labels: map[string]string{"instance": "example"},
		Now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	n := firstSeen("api.example.com")
	n.Description = "a longer text"
	if err := am.Send(context.Background(), []notice.Notice{n}); err != nil {
		t.Fatalf("Send = %v", err)
	}

	if got.Method != http.MethodPost || got.URL.String() != "https://alerts.example.com/api/v2/alerts" {
		t.Errorf("sent %s %s", got.Method, got.URL)
	}
	if ct := got.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	var alerts []alert
	if err := json.Unmarshal(body, &alerts); err != nil || len(alerts) != 1 {
		t.Fatalf("body %s: %v", body, err)
	}
	a := alerts[0]
	for k, v := range map[string]string{"alertname": "SentinelFirstSeen", "severity": "info", "instance": "example", "pair": "destination", "key": "api.example.com"} {
		if a.Labels[k] != v {
			t.Errorf("label %s = %q, want %q", k, a.Labels[k], v)
		}
	}
	if a.Annotations["summary"] != n.Summary || a.Annotations["description"] != "a longer text" {
		t.Errorf("annotations = %v", a.Annotations)
	}
	// It starts when it happened and ends a while after it is sent, so
	// that one sent late is still told once.
	if !a.StartsAt.Equal(at) || !a.EndsAt.After(now) {
		t.Errorf("startsAt %v, endsAt %v", a.StartsAt, a.EndsAt)
	}

	if len(log.begun) != 1 || len(log.done) != 1 {
		t.Fatalf("records begun %d, finished %d; want 1 each", len(log.begun), len(log.done))
	}
	b, d := log.begun[0], log.done[0]
	if b.Kind != audit.KindGate || b.Name != "alerts.example.com" || b.Method != "POST" || b.Path != "/api/v2/alerts" || b.Verdict != audit.Allow {
		t.Errorf("record begun = %+v", b)
	}
	if b.Request == nil || !strings.Contains(b.Request.Text, "SentinelFirstSeen") {
		t.Errorf("the record does not keep what was sent: %+v", b.Request)
	}
	if d.Status != http.StatusOK || d.Error != "" {
		t.Errorf("record finished = %+v", d)
	}
}

func TestAnAnswerThatIsNotASuccessIsAFailureAndRecorded(t *testing.T) {
	log := &recLog{}
	am, err := notice.NewAlertmanager(notice.AlertmanagerConfig{
		URL: "https://alerts.example.com",
		Transport: tripper(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(strings.NewReader("bad")), Header: http.Header{}}, nil
		}),
		Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := am.Send(context.Background(), []notice.Notice{firstSeen("a.example.com")}); err == nil {
		t.Fatal("Send = nil for a 400")
	}
	if len(log.done) != 1 || log.done[0].Status != http.StatusBadRequest {
		t.Errorf("finished = %+v", log.done)
	}
}

func TestASenderThatFailsIsAFailureAndRecorded(t *testing.T) {
	log := &recLog{}
	am, _ := notice.NewAlertmanager(notice.AlertmanagerConfig{
		URL: "https://alerts.example.com",
		Transport: tripper(func(r *http.Request) (*http.Response, error) {
			return nil, errors.New("authd: upstream-not-registered")
		}),
		Log: log,
	})
	if err := am.Send(context.Background(), []notice.Notice{firstSeen("a.example.com")}); err == nil {
		t.Fatal("Send = nil when the sender failed")
	}
	if len(log.done) != 1 || !strings.Contains(log.done[0].Error, "upstream-not-registered") {
		t.Errorf("finished = %+v", log.done)
	}
}

func TestANoticeThatCannotBeRecordedIsNotSent(t *testing.T) {
	sent := false
	am, _ := notice.NewAlertmanager(notice.AlertmanagerConfig{
		URL: "https://alerts.example.com",
		Transport: tripper(func(r *http.Request) (*http.Response, error) {
			sent = true
			return nil, errors.New("unreachable")
		}),
		Log: &recLog{failing: errors.New("disk full")},
	})
	if err := am.Send(context.Background(), []notice.Notice{firstSeen("a.example.com")}); err == nil {
		t.Fatal("Send = nil when it could not be recorded")
	}
	if sent {
		t.Error("it was sent without a record")
	}
}

func TestOnlyAnHTTPSAddressOfAlertmanagerIsTaken(t *testing.T) {
	for _, u := range []string{
		"http://alerts.example.com",
		"alerts.example.com",
		"https://",
		"https://alerts.example.com/?x=1",
		"https://user:pass@alerts.example.com",
		"https://alerts.example.com/#f",
	} {
		if _, err := notice.NewAlertmanager(notice.AlertmanagerConfig{URL: u, Transport: http.DefaultTransport, Log: &recLog{}}); err == nil {
			t.Errorf("NewAlertmanager(%q) = nil error", u)
		}
	}
	for _, u := range []string{"https://alerts.example.com", "https://alerts.example.com:8443/am"} {
		if _, err := notice.NewAlertmanager(notice.AlertmanagerConfig{URL: u, Transport: http.DefaultTransport, Log: &recLog{}}); err != nil {
			t.Errorf("NewAlertmanager(%q) = %v", u, err)
		}
	}
}

func TestAnAnswerIsAnAlertOfItsOwnName(t *testing.T) {
	var body []byte
	am, err := notice.NewAlertmanager(notice.AlertmanagerConfig{
		URL: "https://alerts.example.com",
		Transport: tripper(func(r *http.Request) (*http.Response, error) {
			body, _ = io.ReadAll(r.Body)
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: http.Header{}}, nil
		}),
		Log: &recLog{},
	})
	if err != nil {
		t.Fatal(err)
	}
	n := notice.Notice{Type: notice.TypeAnswer, At: at, Labels: map[string]string{"answer": "allowed", "approval": "ap-1"}, Summary: "s"}
	if err := am.Send(context.Background(), []notice.Notice{n}); err != nil {
		t.Fatal(err)
	}
	var alerts []alert
	if err := json.Unmarshal(body, &alerts); err != nil || len(alerts) != 1 {
		t.Fatalf("posted %s, %v", body, err)
	}
	if l := alerts[0].Labels; l["alertname"] != "SentinelAnswer" || l["answer"] != "allowed" || l["approval"] != "ap-1" || l["severity"] != "info" {
		t.Errorf("labels = %v", l)
	}
}

const noticeSurrogate = "surrogate-for-the-notices-0123456789"

// sendOne sends one notice through a sender with the surrogate given, and
// gives the request that was sent and the records written.
func sendOne(t *testing.T, surrogate string) (*http.Request, *recLog) {
	t.Helper()
	var got *http.Request
	log := &recLog{}
	am, err := notice.NewAlertmanager(notice.AlertmanagerConfig{
		URL:       "https://alerts.example.com",
		Surrogate: surrogate,
		Transport: tripper(func(r *http.Request) (*http.Response, error) {
			got = r
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: http.Header{}}, nil
		}),
		Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := am.Send(context.Background(), []notice.Notice{firstSeen("a.example.com")}); err != nil {
		t.Fatal(err)
	}
	return got, log
}

func TestWithASurrogateTheNoticesCarryItAsABearerAndTheRecordDoesNot(t *testing.T) {
	got, log := sendOne(t, noticeSurrogate)
	if a := got.Header.Values("Authorization"); len(a) != 1 || a[0] != "Bearer "+noticeSurrogate {
		t.Errorf("Authorization = %q, want the surrogate as a bearer", a)
	}
	for _, rec := range append(log.begun, log.done...) {
		if s := fmt.Sprintf("%+v %+v", rec, rec.Request); strings.Contains(s, noticeSurrogate) {
			t.Errorf("the record carries the surrogate: %s", s)
		}
	}
}

func TestWithoutASurrogateTheNoticesCarryNoAuthorization(t *testing.T) {
	got, _ := sendOne(t, "")
	if a := got.Header.Values("Authorization"); len(a) != 0 {
		t.Errorf("Authorization = %q, want none", a)
	}
}

func TestASurrogateThatCannotBeABearerIsNotTakenAndNotTold(t *testing.T) {
	for _, s := range []string{"has a space-0123456789", "line-0123456789\r\nX-Other: 1", "tab-0123456789\there", "non-ascii-0123456789é", "del-0123456789\x7f"} {
		_, err := notice.NewAlertmanager(notice.AlertmanagerConfig{URL: "https://alerts.example.com", Surrogate: s, Transport: http.DefaultTransport, Log: &recLog{}})
		if err == nil {
			t.Errorf("NewAlertmanager(surrogate %q) = nil error", s)
			continue
		}
		if strings.Contains(err.Error(), s) {
			t.Errorf("the error tells the surrogate: %v", err)
		}
	}
}
