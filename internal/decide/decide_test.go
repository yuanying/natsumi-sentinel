package decide_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/decide"
	"github.com/yuanying/natsumi-sentinel/internal/ledger"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

const table = `
destinations:
  - name: api.example.com
    treatment: open
    default: ask
    rules:
      - operation: read
        methods: [GET]
      - operation: pulls.merge
        methods: [PUT]
        path: /repos/{owner}/{repo}/pulls/{number}/merge
        target: [owner, repo]
      - operation: repos.delete
        methods: [DELETE]
        path: /repos/{owner}/{repo}
    operations:
      read: allow
      repos.delete: deny
  - name: allow.example.com
    treatment: open
    default: allow
  - name: deny.example.com
    treatment: open
    default: deny
`

func dest(t *testing.T, name string) (routes.Destination, routes.ApprovalSettings) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "r.yaml"), []byte(table), 0o600); err != nil {
		t.Fatal(err)
	}
	tbl, err := routes.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	d, ok := tbl.Lookup(name, 443)
	if !ok {
		t.Fatalf("no %s", name)
	}
	return d, tbl.Approvals()
}

// fakeLedger keeps what it was asked and answers as told.
type fakeLedger struct {
	grant   *ledger.Grant
	err     error
	looked  []ledger.Facts
	held    []ledger.Facts
	created bool
	// grantFor, when set, gives the grant for one request.
	grantFor func(ledger.Facts) *ledger.Grant
}

func (f *fakeLedger) LookupAll(_ context.Context, facts []ledger.Facts) ([]*ledger.Grant, error) {
	f.looked = append(f.looked, facts...)
	out := make([]*ledger.Grant, len(facts))
	for i, fc := range facts {
		out[i] = f.grant
		if f.grantFor != nil {
			out[i] = f.grantFor(fc)
		}
	}
	return out, f.err
}

func (f *fakeLedger) HoldAll(_ context.Context, facts []ledger.Facts, _ routes.ApprovalSettings) (*ledger.Approval, bool, error) {
	f.held = append(f.held, facts...)
	if f.err != nil {
		return nil, false, f.err
	}
	return &ledger.Approval{ID: "ap-1"}, !f.created, nil
}

func request(t *testing.T, name, method, path, body string) decide.Request {
	d, s := dest(t, name)
	return decide.Request{
		Source: "workspace", Destination: d, Settings: s, Port: 443,
		Method: method, Path: path, Body: []byte(body), BodyComplete: true,
		BodySummary: &audit.Body{Text: body, Size: int64(len(body))},
	}
}

func TestAnOperationTheTableAllowsGoesThroughWithoutTheLedger(t *testing.T) {
	l := &fakeLedger{}
	got := decide.Table{Ledger: l}.Decide(context.Background(), request(t, "api.example.com", "GET", "/repos/o/r", ""))
	if got.Verdict != audit.Allow || got.Operation != "read" || got.Reason == "" {
		t.Errorf("Decide = %+v", got)
	}
	if len(l.looked)+len(l.held) != 0 {
		t.Error("the ledger was asked about an allowed operation")
	}
}

func TestAnOperationTheTableDeniesIsRefusedEvenWithAGrant(t *testing.T) {
	l := &fakeLedger{grant: &ledger.Grant{ID: "gr-1"}}
	got := decide.Table{Ledger: l}.Decide(context.Background(), request(t, "api.example.com", "DELETE", "/repos/o/r", ""))
	if got.Verdict != audit.Deny || got.Operation != "repos.delete" || got.Target != "owner=o repo=r" || got.Grant != "" {
		t.Errorf("Decide = %+v", got)
	}
}

func TestADefaultDecidesWhatNoRuleNames(t *testing.T) {
	for name, want := range map[string]audit.Verdict{"allow.example.com": audit.Allow, "deny.example.com": audit.Deny} {
		got := decide.Table{}.Decide(context.Background(), request(t, name, "POST", "/x", ""))
		if got.Verdict != want || got.Operation != "" {
			t.Errorf("%s: Decide = %+v, want %s", name, got, want)
		}
	}
}

func TestAnAskedOperationWithAGrantGoesThroughOnIt(t *testing.T) {
	l := &fakeLedger{grant: &ledger.Grant{ID: "gr-1"}}
	got := decide.Table{Ledger: l}.Decide(context.Background(), request(t, "api.example.com", "PUT", "/repos/o/r/pulls/5/merge", `{}`))
	if got.Verdict != audit.Allow || got.Grant != "gr-1" || got.Operation != "pulls.merge" || got.Target != "owner=o repo=r" {
		t.Errorf("Decide = %+v", got)
	}
	f := l.looked[0]
	if f.Source != "workspace" || f.Destination != "api.example.com" || f.Operation != "pulls.merge" ||
		len(f.Params) != 3 || f.Fingerprint == "" || !f.Exact {
		t.Errorf("the ledger was asked with %+v", f)
	}
}

func TestAnAskedOperationWithoutAGrantIsHeldForTheOwner(t *testing.T) {
	l := &fakeLedger{}
	req := request(t, "api.example.com", "PUT", "/repos/o/r/pulls/5/merge", `{"a":1}`)
	got := decide.Table{Ledger: l}.Decide(context.Background(), req)
	if got.Verdict != audit.Ask || got.Approval != "ap-1" || !got.ApprovalCreated {
		t.Errorf("Decide = %+v", got)
	}
	h := l.held[0]
	if h.Body == nil || h.Body.Text != `{"a":1}` || h.Method != "PUT" || h.Path != "/repos/o/r/pulls/5/merge" {
		t.Errorf("held %+v", h)
	}
}

func TestARequestNoRuleNamesOnAnAskingDestinationIsHeldAsARawOperation(t *testing.T) {
	l := &fakeLedger{}
	got := decide.Table{Ledger: l}.Decide(context.Background(), request(t, "api.example.com", "POST", "/graphql", `{}`))
	if got.Verdict != audit.Ask || got.Operation != "" {
		t.Errorf("Decide = %+v", got)
	}
	if h := l.held[0]; h.Operation != "" || h.Method != "POST" || h.Path != "/graphql" {
		t.Errorf("held %+v", h)
	}
}

func TestTheFingerprintFollowsTheWholeRequestAndIsNotExactForABodyCutShort(t *testing.T) {
	fp := func(r decide.Request) ledger.Facts {
		l := &fakeLedger{}
		decide.Table{Ledger: l}.Decide(context.Background(), r)
		return l.looked[0]
	}
	base := request(t, "api.example.com", "POST", "/x", "body")
	a := fp(base)
	other := base
	other.Body = []byte("other")
	withQuery := base
	withQuery.Query = "q=1"
	if fp(other).Fingerprint == a.Fingerprint || fp(withQuery).Fingerprint == a.Fingerprint {
		t.Error("the fingerprint does not follow the body and the query")
	}
	if again := fp(base); again.Fingerprint != a.Fingerprint {
		t.Error("the same request gave another fingerprint")
	}
	cut := base
	cut.BodyComplete = false
	if fp(cut).Exact {
		t.Error("a body cut short gave an exact fingerprint")
	}
}

func TestALedgerThatCannotBeUsedLetsNothingAskedThrough(t *testing.T) {
	l := &fakeLedger{err: errors.New("disk I/O error")}
	got := decide.Table{Ledger: l}.Decide(context.Background(), request(t, "api.example.com", "PUT", "/repos/o/r/pulls/5/merge", ``))
	if got.Verdict != audit.Deny || got.Error == "" {
		t.Errorf("Decide = %+v, want a refusal with the ledger's error", got)
	}
	got = decide.Table{}.Decide(context.Background(), request(t, "api.example.com", "POST", "/x", ``))
	if got.Verdict != audit.Deny || got.Error == "" {
		t.Errorf("without a ledger: Decide = %+v", got)
	}
}

type connector func(decide.Request) (decide.Result, error)

func (c connector) Read(_ context.Context, r decide.Request) (decide.Result, error) {
	return c(r)
}

func TestAConnectorNamesTheOperationBeforeTheRules(t *testing.T) {
	c := connector(func(r decide.Request) (decide.Result, error) {
		if r.Path != "/graphql" {
			return decide.Result{}, nil
		}
		return decide.Result{Operations: []decide.Operation{{Name: "repos.delete", Params: []routes.Param{{Name: "owner", Value: "o"}}, Target: []string{"owner"}}}}, nil
	})
	tbl := decide.Table{GitHub: c}
	got := tbl.Decide(context.Background(), ghRequest(t, "api.example.com", "POST", "/graphql", `{}`))
	if got.Verdict != audit.Deny || got.Operation != "repos.delete" || got.Target != "owner=o" {
		t.Errorf("Decide = %+v", got)
	}
	got = tbl.Decide(context.Background(), ghRequest(t, "api.example.com", "GET", "/x", ``))
	if got.Operation != "read" {
		t.Errorf("the rules did not decide what the connector left: %+v", got)
	}
	failing := decide.Table{GitHub: connector(func(decide.Request) (decide.Result, error) {
		return decide.Result{}, errors.New("could not look the node up")
	})}
	if got := failing.Decide(context.Background(), ghRequest(t, "api.example.com", "GET", "/x", ``)); got.Verdict != audit.Deny || got.Error == "" {
		t.Errorf("a failing connector: %+v", got)
	}
}
