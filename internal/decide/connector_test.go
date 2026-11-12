package decide_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/decide"
	"github.com/yuanying/natsumi-sentinel/internal/ledger"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

func result(r decide.Result) decide.Table {
	return decide.Table{GitHub: connector(func(decide.Request) (decide.Result, error) { return r, nil })}
}

func TestARequestTheConnectorReadsAsAReadGoesThroughWithoutTheTable(t *testing.T) {
	l := &fakeLedger{}
	tbl := result(decide.Result{Read: true})
	tbl.Ledger = l
	got := tbl.Decide(context.Background(), ghRequest(t, "deny.example.com", "POST", "/graphql", `{"query":"{viewer{login}}"}`))
	if got.Verdict != audit.Allow || !strings.Contains(got.Reason, "read") || !got.Read {
		t.Errorf("Decide = %+v, want a read let through", got)
	}
	if len(l.looked)+len(l.held) != 0 {
		t.Error("the ledger was asked about a read")
	}
}

func TestARequestTheConnectorRefusesIsDeniedWithItsReasonAndNoTableCanChangeIt(t *testing.T) {
	got := result(decide.Result{Refusal: "a document with two mutations"}).Decide(context.Background(), ghRequest(t, "allow.example.com", "POST", "/graphql", `{}`))
	if got.Verdict != audit.Deny || !got.Fixed || !strings.Contains(got.Reason, "two mutations") || got.Error != "" {
		t.Errorf("Decide = %+v", got)
	}
}

func TestARequestTheConnectorNamesAsAnOperationIsNotARead(t *testing.T) {
	got := result(decide.Result{Operations: []decide.Operation{{Name: "read"}}}).Decide(context.Background(), ghRequest(t, "allow.example.com", "POST", "/graphql", `{}`))
	if got.Verdict != audit.Allow || got.Read {
		t.Errorf("Decide = %+v, want an operation let through, not a read", got)
	}
}

func TestWhatTheConnectorKeepsOfTheBodyIsInTheDecision(t *testing.T) {
	kept := &audit.Body{Text: "old new refs/heads/main\n", Size: 4096}
	got := result(decide.Result{Request: kept, Operations: []decide.Operation{{Name: "read"}}}).Decide(context.Background(), ghRequest(t, "api.example.com", "POST", "/o/r.git/git-receive-pack", "PACK"))
	if got.Request != kept {
		t.Errorf("Request = %+v", got.Request)
	}
}

func ref(op, name string) decide.Operation {
	return decide.Operation{
		Name:        op,
		Params:      []routes.Param{{Name: "owner", Value: "o"}, {Name: "repo", Value: "r"}, {Name: "ref", Value: name}},
		Target:      []string{"owner", "repo", "ref"},
		Fingerprint: "fp-" + name,
		Facts:       []routes.Param{{Name: "kind", Value: "update"}},
	}
}

func TestOneOperationTheTableDeniesRefusesTheWholeRequest(t *testing.T) {
	l := &fakeLedger{}
	tbl := result(decide.Result{Operations: []decide.Operation{ref("read", "refs/heads/a"), ref("repos.delete", "refs/heads/b")}})
	tbl.Ledger = l
	got := tbl.Decide(context.Background(), ghRequest(t, "api.example.com", "POST", "/o/r.git/git-receive-pack", ""))
	if got.Verdict != audit.Deny || got.Fixed || !strings.Contains(got.Reason, "repos.delete") {
		t.Errorf("Decide = %+v", got)
	}
	if got.Operation != "read, repos.delete" || got.Target != "owner=o repo=r ref=refs/heads/a; owner=o repo=r ref=refs/heads/b" {
		t.Errorf("operation = %q, target = %q", got.Operation, got.Target)
	}
	if len(l.looked)+len(l.held) != 0 {
		t.Error("the ledger was asked about a request that is denied")
	}
}

func TestOnlyTheAskedOperationsWithoutAGrantAreHeldTogether(t *testing.T) {
	l := &fakeLedger{grantFor: func(f ledger.Facts) *ledger.Grant {
		if f.Params[2].Value == "refs/heads/b" {
			return &ledger.Grant{ID: "gr-b"}
		}
		return nil
	}}
	tbl := result(decide.Result{Operations: []decide.Operation{ref("read", "refs/heads/x"), ref("pulls.merge", "refs/heads/a"), ref("pulls.merge", "refs/heads/b"), ref("pulls.merge", "refs/heads/c")}})
	tbl.Ledger = l
	got := tbl.Decide(context.Background(), ghRequest(t, "api.example.com", "POST", "/o/r.git/git-receive-pack", ""))
	if got.Verdict != audit.Ask || got.Approval != "ap-1" {
		t.Fatalf("Decide = %+v", got)
	}
	if len(l.looked) != 3 {
		t.Errorf("looked up %d; want the three asked about", len(l.looked))
	}
	if len(l.held) != 2 || l.held[0].Params[2].Value != "refs/heads/a" || l.held[1].Params[2].Value != "refs/heads/c" {
		t.Fatalf("held = %+v", l.held)
	}
	h := l.held[0]
	if h.Fingerprint != "fp-refs/heads/a" || !h.Exact || len(h.Facts) != 1 || h.Operation != "pulls.merge" {
		t.Errorf("held facts = %+v", h)
	}
}

func TestWhenEveryAskedOperationHasAGrantTheRequestGoesThrough(t *testing.T) {
	l := &fakeLedger{grantFor: func(f ledger.Facts) *ledger.Grant { return &ledger.Grant{ID: "gr-" + f.Params[2].Value[11:]} }}
	tbl := result(decide.Result{Operations: []decide.Operation{ref("pulls.merge", "refs/heads/a"), ref("pulls.merge", "refs/heads/b")}})
	tbl.Ledger = l
	got := tbl.Decide(context.Background(), ghRequest(t, "api.example.com", "POST", "/o/r.git/git-receive-pack", ""))
	if got.Verdict != audit.Allow || got.Grant != "gr-a,gr-b" {
		t.Errorf("Decide = %+v", got)
	}
}

func TestAnOperationWithoutItsOwnFingerprintTakesTheRequests(t *testing.T) {
	l := &fakeLedger{}
	tbl := result(decide.Result{Operations: []decide.Operation{{Name: "pulls.merge"}}})
	tbl.Ledger = l
	req := ghRequest(t, "api.example.com", "POST", "/graphql", `{"query":"mutation{x}"}`)
	tbl.Decide(context.Background(), req)
	other := ghRequest(t, "api.example.com", "POST", "/graphql", `{"query":"mutation{y}"}`)
	tbl.Decide(context.Background(), other)
	if len(l.held) != 2 || l.held[0].Fingerprint == "" || l.held[0].Fingerprint == l.held[1].Fingerprint {
		t.Errorf("held = %+v", l.held)
	}
}

func TestARuleWithBodyFieldsDecidesByTheBody(t *testing.T) {
	d := routesFrom(t, `
destinations:
  - name: api.example.com
    treatment: open
    default: ask
    rules:
      - operation: repo.create.private
        methods: [POST]
        path: /user/repos
        body: {private: "true"}
      - operation: repo.create
        methods: [POST]
        path: /user/repos
    operations:
      repo.create.private: allow
      repo.create: deny
`)
	req := decide.Request{Source: "workspace", Destination: d, Port: 443, Method: "POST", Path: "/user/repos", Body: []byte(`{"name":"x","private":true}`), BodyComplete: true}
	if got := (decide.Table{}).Decide(context.Background(), req); got.Verdict != audit.Allow || got.Operation != "repo.create.private" {
		t.Errorf("private: %+v", got)
	}
	req.Body = []byte(`{"name":"x"}`)
	if got := (decide.Table{}).Decide(context.Background(), req); got.Verdict != audit.Deny || got.Operation != "repo.create" {
		t.Errorf("public: %+v", got)
	}
}

func routesFrom(t *testing.T, yaml string) routes.Destination {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "r.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	tbl, err := routes.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := tbl.Lookup("api.example.com", 443)
	return d
}

// ghRequest is a request to a destination the GitHub connector reads.
func ghRequest(t *testing.T, name, method, path, body string) decide.Request {
	t.Helper()
	r := request(t, name, method, path, body)
	r.Destination.GitHub = &routes.GitHub{API: name}
	return r
}

func TestAGitHubDestinationWithoutAConnectorIsRefused(t *testing.T) {
	got := decide.Table{}.Decide(context.Background(), ghRequest(t, "allow.example.com", "GET", "/x", ""))
	if got.Verdict != audit.Deny || got.Error == "" {
		t.Errorf("Decide = %+v", got)
	}
}
