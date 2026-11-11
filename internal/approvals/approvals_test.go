package approvals_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/approvals"
	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/ledger"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

const table = `
destinations:
  - name: api.example.com
    treatment: open
    default: ask
    rules:
      - operation: pulls.merge
        methods: [PUT]
        path: /repos/{owner}/{repo}/pulls/{number}/merge
        target: [owner, repo]
      - operation: repos.delete
        methods: [DELETE]
        path: /repos/{owner}/{repo}
      - operation: read
        methods: [GET]
    operations:
      repos.delete: deny
      read: allow
  - name: gh.example.com
    treatment: open
    default: ask
    github: {}
    rules:
      - operation: pr.merge
        methods: [PUT]
        path: /repos/{owner}/{repo}/pulls/{number}/merge
        body: {sha: "{sha}"}
        target: [owner, repo, number]
  - name: closed.example.com
    treatment: deny
approvals:
  durations: [1h, forever]
`

// failingLog is the audit log, made to fail its writes when told.
type failingLog struct {
	*audit.Log
	fail bool
}

func (f *failingLog) Write(ctx context.Context, rec *audit.Record) error {
	if f.fail {
		return errors.New("disk full")
	}
	return f.Log.Write(ctx, rec)
}

type env struct {
	t      *testing.T
	ledger *ledger.Ledger
	log    *failingLog
	table  *routes.Table
	owner  http.Handler
	agent  http.Handler
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "r.yaml"), []byte(table), 0o600); err != nil {
		t.Fatal(err)
	}
	tbl, err := routes.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	l, err := ledger.Open(filepath.Join(dir, "ledger.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	a, err := audit.Open(filepath.Join(dir, "audit.db"), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	e := &env{t: t, ledger: l, log: &failingLog{Log: a}, table: tbl}
	routesFn := func() *routes.Table { return e.table }
	e.owner = approvals.Owner(approvals.OwnerConfig{Ledger: l, Log: e.log, Ping: 50 * time.Millisecond})
	e.agent = approvals.Agent(approvals.AgentConfig{Source: "workspace", Ledger: l, Log: e.log, Routes: routesFn})
	return e
}

func (e *env) do(h http.Handler, method, path, body string) (int, map[string]any) {
	e.t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	out := map[string]any{}
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			e.t.Fatalf("%s %s: the answer is not JSON: %q", method, path, w.Body.String())
		}
	}
	if ct := w.Header().Get("Content-Type"); w.Body.Len() > 0 && ct != "application/json" {
		e.t.Errorf("%s %s: Content-Type = %q", method, path, ct)
	}
	return w.Code, out
}

func (e *env) hold(source, number string) *ledger.Approval {
	e.t.Helper()
	a, _, err := e.ledger.Hold(context.Background(), ledger.Facts{
		Source: source, Destination: "api.example.com", Method: "PUT",
		Path:      "/repos/o/r/pulls/" + number + "/merge",
		Operation: "pulls.merge",
		Params:    []routes.Param{{Name: "owner", Value: "o"}, {Name: "repo", Value: "r"}, {Name: "number", Value: number}},
		Target:    []string{"owner", "repo"}, Fingerprint: "fp-" + source + number, Exact: true,
	}, e.table.Approvals())
	if err != nil {
		e.t.Fatal(err)
	}
	return a
}

func (e *env) records(kind audit.Kind) []*audit.Record {
	e.t.Helper()
	recs, err := e.log.List(context.Background(), audit.Query{Kind: kind})
	if err != nil {
		e.t.Fatal(err)
	}
	return recs
}

func list(v any) []any {
	l, _ := v.([]any)
	return l
}

func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func TestTheOwnerListsTheOpenApprovalsAndReadsOne(t *testing.T) {
	e := newEnv(t)
	a := e.hold("workspace", "5")
	b := e.hold("workspace", "6")
	_, _ = e.ledger.Answer(context.Background(), b.ID, ledger.Answer{Allow: false}, nil)

	code, out := e.do(e.owner, "GET", "/v1/approvals", "")
	if code != 200 || len(list(out["approvals"])) != 1 || obj(list(out["approvals"])[0])["id"] != a.ID {
		t.Errorf("GET /v1/approvals = %d %v", code, out)
	}
	code, out = e.do(e.owner, "GET", "/v1/approvals?state=all", "")
	if code != 200 || len(list(out["approvals"])) != 2 {
		t.Errorf("state=all = %d %v", code, out)
	}
	code, out = e.do(e.owner, "GET", "/v1/approvals/"+a.ID, "")
	if code != 200 || out["id"] != a.ID || out["summary"] == "" || len(list(out["choices"])) != 3 || len(list(out["items"])) != 1 {
		t.Errorf("GET one = %d %v", code, out)
	}
	if code, _ := e.do(e.owner, "GET", "/v1/approvals/ap-none", ""); code != 404 {
		t.Errorf("an unknown approval = %d, want 404", code)
	}
	if code, _ := e.do(e.owner, "GET", "/v1/approvals?state=maybe", ""); code != 400 {
		t.Errorf("an unknown state = %d, want 400", code)
	}
}

func TestTheOwnersAnswerTakesEffectOnceAndIsRecorded(t *testing.T) {
	e := newEnv(t)
	a := e.hold("workspace", "5")
	code, out := e.do(e.owner, "POST", "/v1/approvals/"+a.ID+"/answer", `{"answer":"allow","choice":"1h"}`)
	if code != 200 || out["state"] != "allowed" || len(list(out["grants"])) != 1 {
		t.Fatalf("answer = %d %v", code, out)
	}
	recs := e.records(audit.KindAnswer)
	if len(recs) != 1 || recs[0].Verdict != audit.Allow || recs[0].Approval != a.ID || recs[0].Grant == "" ||
		recs[0].Operation != "pulls.merge" || recs[0].Target != "owner=o repo=r" || recs[0].Source != "workspace" || !strings.Contains(recs[0].Reason, "1h") {
		t.Errorf("answer records = %+v", recs)
	}
	if code, _ := e.do(e.owner, "POST", "/v1/approvals/"+a.ID+"/answer", `{"answer":"deny"}`); code != 409 {
		t.Errorf("a second answer = %d, want 409", code)
	}
}

func TestAnAnswerTheApprovalCannotTakeIsRefused(t *testing.T) {
	e := newEnv(t)
	a := e.hold("workspace", "5")
	for body, want := range map[string]int{
		`{"answer":"allow","choice":"30d"}`: 400,
		`{"answer":"allow"}`:                400,
		`{"answer":"maybe"}`:                400,
		`{"answer":"deny","extra":1}`:       400,
		`not json`:                          400,
	} {
		if code, _ := e.do(e.owner, "POST", "/v1/approvals/"+a.ID+"/answer", body); code != want {
			t.Errorf("%s = %d, want %d", body, code, want)
		}
	}
	if code, _ := e.do(e.owner, "POST", "/v1/approvals/ap-none/answer", `{"answer":"deny"}`); code != 404 {
		t.Errorf("an unknown approval = %d, want 404", code)
	}
	code, out := e.do(e.owner, "POST", "/v1/approvals/"+a.ID+"/answer", `{"answer":"deny"}`)
	if code != 200 || out["state"] != "denied" {
		t.Errorf("deny = %d %v", code, out)
	}
	if recs := e.records(audit.KindAnswer); len(recs) != 1 || recs[0].Verdict != audit.Deny {
		t.Errorf("records = %+v", recs)
	}
}

func TestAnAnswerThatCannotBeRecordedIsNotTaken(t *testing.T) {
	e := newEnv(t)
	a := e.hold("workspace", "5")
	e.log.fail = true
	if code, _ := e.do(e.owner, "POST", "/v1/approvals/"+a.ID+"/answer", `{"answer":"allow","choice":"once"}`); code != 503 {
		t.Errorf("answer = %d, want 503", code)
	}
	got, _ := e.ledger.Get(context.Background(), a.ID)
	if got.State != ledger.Pending {
		t.Errorf("state = %s, want still open", got.State)
	}
}

func TestTheOwnerListsTheGrantsAndRevokesOne(t *testing.T) {
	e := newEnv(t)
	a := e.hold("workspace", "5")
	_, out := e.do(e.owner, "POST", "/v1/approvals/"+a.ID+"/answer", `{"answer":"allow","choice":"forever"}`)
	id, _ := list(out["grants"])[0].(string)
	code, out := e.do(e.owner, "GET", "/v1/grants", "")
	if code != 200 || len(list(out["grants"])) != 1 || obj(list(out["grants"])[0])["id"] != id {
		t.Fatalf("grants = %d %v", code, out)
	}
	if code, _ := e.do(e.owner, "DELETE", "/v1/grants/"+id, ""); code != 200 {
		t.Errorf("revoke = %d", code)
	}
	if _, out := e.do(e.owner, "GET", "/v1/grants", ""); len(list(out["grants"])) != 0 {
		t.Errorf("grants after revoking = %v", out)
	}
	if code, _ := e.do(e.owner, "DELETE", "/v1/grants/"+id, ""); code != 404 {
		t.Errorf("revoke again = %d, want 404", code)
	}
	recs := e.records(audit.KindAnswer)
	if len(recs) != 2 || recs[0].Grant != id || recs[0].Approval != a.ID || !strings.Contains(recs[0].Reason, "revoked") {
		t.Errorf("records = %+v", recs)
	}
}

func TestTheOwnerReadsTheRecordsPageByPage(t *testing.T) {
	e := newEnv(t)
	for _, n := range []string{"a", "b", "c"} {
		_ = e.log.Write(context.Background(), &audit.Record{Time: time.Now(), Kind: audit.KindHTTP, Name: n})
	}
	code, out := e.do(e.owner, "GET", "/v1/records?limit=2", "")
	recs := list(out["records"])
	if code != 200 || len(recs) != 2 || obj(recs[0])["name"] != "c" || out["next"] == nil {
		t.Fatalf("records = %d %v", code, out)
	}
	next := int64(out["next"].(float64))
	_, out = e.do(e.owner, "GET", "/v1/records?limit=2&before="+itoa(next), "")
	if recs := list(out["records"]); len(recs) != 1 || obj(recs[0])["name"] != "a" || out["next"] != nil {
		t.Errorf("the next page = %v", out)
	}
	id := int64(obj(recs[0])["id"].(float64))
	if code, out := e.do(e.owner, "GET", "/v1/records/"+itoa(id), ""); code != 200 || out["name"] != "c" {
		t.Errorf("one record = %d %v", code, out)
	}
	if code, _ := e.do(e.owner, "GET", "/v1/records/999", ""); code != 404 {
		t.Errorf("an unknown record = %d, want 404", code)
	}
	if code, _ := e.do(e.owner, "GET", "/v1/records?kind=http&verdict=deny&source=workspace", ""); code != 200 {
		t.Errorf("narrowed = %d", code)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestTheEventsAreStreamedOneJSONObjectALine(t *testing.T) {
	e := newEnv(t)
	srv := httptest.NewServer(e.owner)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/v1/events")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if ct := resp.Header.Get("Content-Type"); ct != "application/x-ndjson" {
		t.Errorf("Content-Type = %q", ct)
	}
	lines := bufio.NewScanner(resp.Body)
	next := func() map[string]any {
		t.Helper()
		for lines.Scan() {
			var m map[string]any
			if err := json.Unmarshal(lines.Bytes(), &m); err != nil {
				t.Fatalf("not JSON: %q", lines.Text())
			}
			if m["type"] != "ping" {
				return m
			}
		}
		t.Fatalf("the stream ended: %v", lines.Err())
		return nil
	}
	if m := next(); m["type"] != "hello" {
		t.Fatalf("first line = %v, want hello", m)
	}
	a := e.hold("workspace", "5")
	if m := next(); m["type"] != "approval.created" || obj(m["approval"])["id"] != a.ID {
		t.Errorf("event = %v", m)
	}
	_, _ = e.ledger.Answer(context.Background(), a.ID, ledger.Answer{Allow: false}, nil)
	if m := next(); m["type"] != "approval.closed" || obj(m["approval"])["state"] != "denied" {
		t.Errorf("event = %v", m)
	}
}

func TestTheWorkspaceReadsOnlyItsOwnState(t *testing.T) {
	e := newEnv(t)
	mine := e.hold("workspace", "5")
	granted := e.hold("workspace", "6")
	_, _ = e.ledger.Answer(context.Background(), granted.ID, ledger.Answer{Allow: true, Choice: "1h"}, nil)
	theirs := e.hold("server", "7")
	_, _ = e.ledger.Answer(context.Background(), e.hold("server", "8").ID, ledger.Answer{Allow: true, Choice: "1h"}, nil)
	for _, r := range []audit.Record{
		{Source: "workspace", Kind: audit.KindHTTP, Verdict: audit.Deny, Name: "api.example.com", Reason: "denied by the table"},
		{Source: "workspace", Kind: audit.KindHTTP, Verdict: audit.Ask, Name: "api.example.com", Approval: mine.ID},
		{Source: "workspace", Kind: audit.KindHTTP, Verdict: audit.Allow, Name: "api.example.com"},
		{Source: "server", Kind: audit.KindHTTP, Verdict: audit.Deny, Name: "api.example.com"},
	} {
		r.Time = time.Now()
		_ = e.log.Write(context.Background(), &r)
	}

	code, out := e.do(e.agent, "GET", "/v1/status", "")
	if code != 200 {
		t.Fatalf("status = %d", code)
	}
	if as := list(out["approvals"]); len(as) != 1 || obj(as[0])["id"] != mine.ID {
		t.Errorf("approvals = %v", out["approvals"])
	}
	if gs := list(out["grants"]); len(gs) != 1 || obj(gs[0])["approval"] != granted.ID {
		t.Errorf("grants = %v", out["grants"])
	}
	refused := list(out["refused"])
	if len(refused) != 2 || obj(refused[0])["verdict"] != "ask" || obj(refused[1])["reason"] != "denied by the table" {
		t.Errorf("refused = %v", refused)
	}
	if code, out := e.do(e.agent, "GET", "/v1/approvals/"+mine.ID, ""); code != 200 || out["id"] != mine.ID {
		t.Errorf("own approval = %d %v", code, out)
	}
	if code, _ := e.do(e.agent, "GET", "/v1/approvals/"+theirs.ID, ""); code != 404 {
		t.Errorf("another source's approval = %d, want 404", code)
	}
	for _, path := range []string{"/v1/approvals/" + mine.ID + "/answer", "/v1/grants/x"} {
		for _, m := range []string{"POST", "DELETE"} {
			if code, _ := e.do(e.agent, m, path, `{"answer":"allow","choice":"once"}`); code != 404 && code != 405 {
				t.Errorf("%s %s on the workspace's side = %d; it must not answer", m, path, code)
			}
		}
	}
}

func TestTheWorkspaceAsksBeforehandForConcreteOperationsAsOneApproval(t *testing.T) {
	e := newEnv(t)
	code, out := e.do(e.agent, "POST", "/v1/approvals", `{"items":[
		{"destination":"api.example.com","operation":"pulls.merge","params":{"owner":"o","repo":"r","number":"5"}},
		{"destination":"api.example.com","operation":"pulls.merge","params":{"owner":"o","repo":"r","number":"6"}}]}`)
	if code != 201 || out["kind"] != "beforehand" || len(list(out["items"])) != 2 || len(list(out["choices"])) != 1 {
		t.Fatalf("ask = %d %v", code, out)
	}
	recs := e.records(audit.KindAgent)
	if len(recs) != 1 || recs[0].Approval != out["id"] || recs[0].Source != "workspace" || recs[0].Verdict != audit.Ask {
		t.Errorf("records = %+v", recs)
	}
}

func TestAskingBeforehandForWhatCannotBeAskedIsRefused(t *testing.T) {
	e := newEnv(t)
	item := func(dest, op, params string) string {
		return `{"items":[{"destination":"` + dest + `","operation":"` + op + `","params":` + params + `}]}`
	}
	for name, tc := range map[string]struct {
		body string
		want int
	}{
		"a scope":                       {`{"items":[{"destination":"api.example.com","operation":"pulls.merge","params":{"owner":"o","repo":"r","number":"5"}}],"scope":"forever"}`, 400},
		"no items":                      {`{"items":[]}`, 400},
		"not open":                      {item("closed.example.com", "pulls.merge", `{}`), 400},
		"not in the table":              {item("unknown.example.com", "pulls.merge", `{}`), 400},
		"an operation no rule names":    {item("api.example.com", "pulls.close", `{}`), 400},
		"a missing parameter":           {item("api.example.com", "pulls.merge", `{"owner":"o","repo":"r"}`), 400},
		"a parameter the rule lacks":    {item("api.example.com", "pulls.merge", `{"owner":"o","repo":"r","number":"5","sha":"x"}`), 400},
		"an empty parameter":            {item("api.example.com", "pulls.merge", `{"owner":"o","repo":"r","number":""}`), 400},
		"an operation the table denies": {item("api.example.com", "repos.delete", `{"owner":"o","repo":"r"}`), 403},
		"an operation already allowed":  {item("api.example.com", "read", `{}`), 400},
	} {
		t.Run(name, func(t *testing.T) {
			if code, out := e.do(e.agent, "POST", "/v1/approvals", tc.body); code != tc.want || out["error"] == "" {
				t.Errorf("ask = %d %v, want %d with an error", code, out, tc.want)
			}
		})
	}
	if all, _ := e.ledger.Approvals(context.Background(), ledger.Filter{}); len(all) != 0 {
		t.Errorf("approvals made = %d, want none", len(all))
	}
}

func TestAskingBeforehandThatCannotBeRecordedIsNotTaken(t *testing.T) {
	e := newEnv(t)
	e.log.fail = true
	code, _ := e.do(e.agent, "POST", "/v1/approvals", `{"items":[{"destination":"api.example.com","operation":"pulls.merge","params":{"owner":"o","repo":"r","number":"5"}}]}`)
	if code != 503 {
		t.Errorf("ask = %d, want 503", code)
	}
}

func TestAMergeAskedForBeforehandOnGitHubTakesItsHeadSHAAndTheRepositoryWithoutCase(t *testing.T) {
	e := newEnv(t)
	code, out := e.do(e.agent, "POST", "/v1/approvals", `{"items":[
		{"destination":"gh.example.com","operation":"pr.merge","params":{"owner":"Example","repo":"R","number":"5","sha":"abc"}}]}`)
	if code != 201 {
		t.Fatalf("ask = %d %v", code, out)
	}
	item := list(out["items"])[0].(map[string]any)
	if item["targetText"] != "owner=example repo=r number=5" {
		t.Errorf("item = %v", item)
	}
	code, out = e.do(e.agent, "POST", "/v1/approvals", `{"items":[
		{"destination":"gh.example.com","operation":"pr.merge","params":{"owner":"o","repo":"r","number":"5"}}]}`)
	if code != 400 || !strings.Contains(fmt.Sprint(out["error"]), "sha") {
		t.Errorf("a merge without its SHA = %d %v", code, out)
	}
}
