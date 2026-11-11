package observe_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/authdclient"
	"github.com/yuanying/natsumi-sentinel/internal/metrics"
	"github.com/yuanying/natsumi-sentinel/internal/observe"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

// fakeLog is an audit log that fails when told to.
type fakeLog struct {
	fail  error
	calls []string
}

func (f *fakeLog) Write(_ context.Context, rec *audit.Record) error {
	f.calls = append(f.calls, "write")
	rec.ID = 7
	return f.fail
}

func (f *fakeLog) Begin(_ context.Context, rec *audit.Record) error {
	f.calls = append(f.calls, "begin")
	rec.ID = 8
	return f.fail
}

func (f *fakeLog) Finish(_ context.Context, rec *audit.Record) error {
	f.calls = append(f.calls, "finish")
	return f.fail
}

func TestTheRecorderWritesThroughAndTellsWhatWasWrittenAndHowItWent(t *testing.T) {
	inner := &fakeLog{}
	var events []observe.Event
	r := observe.NewRecorder(inner, func(ev observe.Event) { events = append(events, ev) })

	rec := &audit.Record{Kind: audit.KindHTTP, Name: "api.example.com"}
	if err := r.Begin(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
	rec.Status = 200
	if err := r.Finish(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
	inner.fail = errors.New("disk full")
	if err := r.Write(context.Background(), &audit.Record{Kind: audit.KindDNS}); !errors.Is(err, inner.fail) {
		t.Fatalf("Write = %v, want the log's error", err)
	}

	if got := strings.Join(inner.calls, ","); got != "begin,finish,write" {
		t.Errorf("the log was called %s", got)
	}
	if len(events) != 3 {
		t.Fatalf("told %d events, want 3", len(events))
	}
	if events[0].Stage != observe.Begin || events[1].Stage != observe.Finish || events[2].Stage != observe.Write {
		t.Errorf("stages = %v %v %v", events[0].Stage, events[1].Stage, events[2].Stage)
	}
	if events[1].Record.ID != 8 || events[1].Record.Status != 200 {
		t.Errorf("the finished record told = %+v, want the one written", events[1].Record)
	}
	if events[2].Err == nil {
		t.Error("the failed write was told without its error")
	}
	// What is told is a copy: the gate going on with its record does
	// not change it.
	rec.Status = 500
	if events[1].Record.Status != 200 {
		t.Error("the event shares the gate's record")
	}
}

func table(t *testing.T) func() *routes.Table {
	t.Helper()
	dir := t.TempDir()
	yaml := `
destinations:
  - name: api.example.com
    treatment: open
    default: allow
  - name: closed.example.com
    treatment: deny
`
	if err := os.WriteFile(filepath.Join(dir, "routes.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	tbl, err := routes.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return func() *routes.Table { return tbl }
}

func page(t *testing.T, reg *prometheus.Registry) string {
	t.Helper()
	srv := httptest.NewServer(metrics.Handler(reg))
	defer srv.Close()
	resp, err := http.Get(srv.URL + metrics.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func wantLines(t *testing.T, page string, lines ...string) {
	t.Helper()
	for _, l := range lines {
		if !strings.Contains(page, l+"\n") {
			t.Errorf("the metrics do not carry %q", l)
		}
	}
}

func TestRequestsAreCountedByDestinationTreatmentAndVerdict(t *testing.T) {
	reg := metrics.NewRegistry("sentinel", "dev")
	m := observe.NewGateMetrics(reg, table(t), []string{"sentinel.internal"})

	finish := func(rec audit.Record) { m.Observe(observe.Event{Stage: observe.Finish, Record: rec}) }
	write := func(rec audit.Record) { m.Observe(observe.Event{Stage: observe.Write, Record: rec}) }
	finish(audit.Record{Source: "workspace", Kind: audit.KindHTTP, Treatment: "open", Name: "api.example.com", Verdict: audit.Allow})
	finish(audit.Record{Source: "workspace", Kind: audit.KindHTTP, Treatment: "open", Name: "api.example.com", Verdict: audit.Allow})
	write(audit.Record{Source: "workspace", Kind: audit.KindHTTP, Treatment: "open", Name: "api.example.com", Verdict: audit.Deny})
	write(audit.Record{Source: "workspace", Kind: audit.KindConnection, Treatment: "deny", Name: "closed.example.com", Verdict: audit.Deny})
	// Names the workspace makes up are not labels of their own.
	write(audit.Record{Source: "workspace", Kind: audit.KindConnection, Treatment: "deny", Name: "made-up-1.example.net", Verdict: audit.Deny})
	write(audit.Record{Source: "workspace", Kind: audit.KindDNS, Treatment: "deny", Name: "made-up-2.example.net", Verdict: audit.Deny})
	write(audit.Record{Source: "workspace", Kind: audit.KindDNS, Name: "sentinel.internal", Verdict: audit.Allow})
	finish(audit.Record{Source: "workspace", Kind: audit.KindPassthrough, Treatment: "passthrough", Address: "192.0.2.10:5432", Verdict: audit.Allow})
	// A begun record is not counted until it is finished.
	m.Observe(observe.Event{Stage: observe.Begin, Record: audit.Record{Source: "workspace", Kind: audit.KindHTTP, Treatment: "open", Name: "api.example.com", Verdict: audit.Allow}})
	// Nor is a record that could not be written: it did not happen.
	m.Observe(observe.Event{Stage: observe.Write, Err: errors.New("disk full"), Record: audit.Record{Source: "workspace", Kind: audit.KindDNS, Name: "api.example.com", Verdict: audit.Allow}})

	p := page(t, reg)
	wantLines(t, p,
		`sentinel_requests_total{destination="api.example.com",kind="http",source="workspace",treatment="open",verdict="allow"} 2`,
		`sentinel_requests_total{destination="api.example.com",kind="http",source="workspace",treatment="open",verdict="deny"} 1`,
		`sentinel_requests_total{destination="closed.example.com",kind="connection",source="workspace",treatment="deny",verdict="deny"} 1`,
		`sentinel_requests_total{destination="(not-listed)",kind="connection",source="workspace",treatment="deny",verdict="deny"} 1`,
		`sentinel_requests_total{destination="(not-listed)",kind="dns",source="workspace",treatment="deny",verdict="deny"} 1`,
		`sentinel_requests_total{destination="sentinel.internal",kind="dns",source="workspace",treatment="",verdict="allow"} 1`,
		`sentinel_requests_total{destination="",kind="passthrough",source="workspace",treatment="passthrough",verdict="allow"} 1`,
	)
	if strings.Contains(p, "made-up") || strings.Contains(p, "192.0.2.10") {
		t.Error("a name or an address the workspace chose is in the metrics")
	}
}

func TestRecordsThatCannotBeWrittenAreCountedByStage(t *testing.T) {
	reg := metrics.NewRegistry("sentinel", "dev")
	m := observe.NewGateMetrics(reg, table(t), nil)
	wantLines(t, page(t, reg),
		`sentinel_audit_write_failures_total{stage="begin"} 0`,
		`sentinel_audit_write_failures_total{stage="finish"} 0`,
		`sentinel_audit_write_failures_total{stage="write"} 0`,
	)
	fail := errors.New("disk full")
	m.Observe(observe.Event{Stage: observe.Begin, Err: fail, Record: audit.Record{Kind: audit.KindHTTP}})
	m.Observe(observe.Event{Stage: observe.Write, Err: fail, Record: audit.Record{Kind: audit.KindDNS}})
	m.Observe(observe.Event{Stage: observe.Write, Err: fail, Record: audit.Record{Kind: audit.KindDNS}})
	wantLines(t, page(t, reg),
		`sentinel_audit_write_failures_total{stage="begin"} 1`,
		`sentinel_audit_write_failures_total{stage="write"} 2`,
	)
}

func TestARoutingTableThatWasNotTakenIsCounted(t *testing.T) {
	reg := metrics.NewRegistry("sentinel", "dev")
	m := observe.NewGateMetrics(reg, table(t), nil)
	m.Observe(observe.Event{Stage: observe.Write, Record: audit.Record{Kind: audit.KindConfig, Verdict: audit.Allow}})
	m.Observe(observe.Event{Stage: observe.Write, Record: audit.Record{Kind: audit.KindConfig, Verdict: audit.Deny}})
	// It is counted even when its record could not be written.
	m.Observe(observe.Event{Stage: observe.Write, Err: errors.New("disk full"), Record: audit.Record{Kind: audit.KindConfig, Verdict: audit.Deny}})
	p := page(t, reg)
	wantLines(t, p, `sentinel_routes_reload_failures_total 2`)
	if strings.Contains(p, `kind="config"`) {
		t.Error("reading the table again is counted as a request")
	}
}

type tripper func(*http.Request) (*http.Response, error)

func (f tripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestUpstreamFailuresAreCountedByDestinationAndReason(t *testing.T) {
	reg := metrics.NewRegistry("sentinel", "dev")
	m := observe.NewGateMetrics(reg, table(t), nil)
	var next error
	rt := m.Upstream(tripper(func(r *http.Request) (*http.Response, error) {
		if next != nil {
			return nil, next
		}
		return &http.Response{StatusCode: 502, Body: http.NoBody}, nil
	}))
	send := func(err error) {
		next = err
		req, _ := http.NewRequest(http.MethodGet, "https://api.example.com:443/x?y=1", nil)
		resp, _ := rt.RoundTrip(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
	}
	send(&authdclient.Error{Reason: authdclient.ReasonSurrogateMismatch})
	send(&authdclient.Error{Reason: authdclient.ReasonUpstreamUnreachable})
	send(&authdclient.Error{Reason: "some-reason-from-a-newer-authd"})
	send(errors.New("dial unix: no such file"))
	// A 502 from the upstream itself is an answer, not a failure.
	send(nil)
	// The workspace going away is not the upstream failing.
	send(context.Canceled)

	wantLines(t, page(t, reg),
		`sentinel_upstream_failures_total{destination="api.example.com",reason="surrogate-mismatch"} 1`,
		`sentinel_upstream_failures_total{destination="api.example.com",reason="upstream-unreachable"} 1`,
		`sentinel_upstream_failures_total{destination="api.example.com",reason="other"} 1`,
		`sentinel_upstream_failures_total{destination="api.example.com",reason="authd-unreachable"} 1`,
	)
}

func TestTheApprovalsWaitingAreReadFromTheLedgerAtEachScrape(t *testing.T) {
	reg := metrics.NewRegistry("sentinel", "dev")
	var (
		n   = 2
		err error
	)
	observe.NewApprovalsPending(reg, func(context.Context) (int, error) { return n, err }, nil)
	wantLines(t, page(t, reg), `sentinel_approvals_pending 2`)
	n = 5
	wantLines(t, page(t, reg), `sentinel_approvals_pending 5`)

	// A ledger that cannot be read leaves the series out, and the rest of
	// the page is still served.
	err = errors.New("database is locked")
	got := page(t, reg)
	if strings.Contains(got, "sentinel_approvals_pending ") {
		t.Errorf("the metrics carry a count the ledger did not give:\n%s", got)
	}
	wantLines(t, got, `sentinel_build_info{version="dev"} 1`)
}
