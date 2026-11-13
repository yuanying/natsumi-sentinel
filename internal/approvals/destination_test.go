package approvals_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/yuanying/natsumi-sentinel/internal/approvals"
	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/ledger"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
	"github.com/yuanying/natsumi-sentinel/internal/upstream"
)

// withGrants turns the destination grants on in both doors, and keeps
// what the owner's door tells of the grants it gives.
func (e *env) withGrants() *[]*ledger.Grant {
	e.t.Helper()
	inside, err := upstream.ParseDomains([]string{"inside.example"})
	if err != nil {
		e.t.Fatal(err)
	}
	var granted []*ledger.Grant
	dc := &approvals.DestinationConfig{
		Routes:         func() *routes.Table { return e.table },
		Fixed:          []string{"sentinel.internal"},
		SearchSuffixes: []string{"svc.cluster.local"},
		Inside:         inside,
		Granted:        func(g *ledger.Grant) { granted = append(granted, g) },
	}
	e.owner = approvals.Owner(approvals.OwnerConfig{Ledger: e.ledger, Log: e.log, Ping: 50 * time.Millisecond, Destinations: dc})
	e.agent = approvals.Agent(approvals.AgentConfig{Source: "workspace", Ledger: e.ledger, Log: e.log, Routes: func() *routes.Table { return e.table }, Destinations: dc})
	return &granted
}

func (e *env) refuse(source string, names ...string) {
	e.t.Helper()
	for _, n := range names {
		if _, err := e.ledger.RememberRefused(context.Background(), source, n); err != nil {
			e.t.Fatal(err)
		}
	}
}

func names(v any) []string {
	var out []string
	for _, x := range list(v) {
		out = append(out, obj(x)["name"].(string))
	}
	return out
}

func TestTheOwnerListsTheRefusedNamesWithTheirChoicesAndOptions(t *testing.T) {
	e := newEnv(t)
	e.withGrants()
	e.refuse("workspace", "a.b.example.net", "api.inside.example")
	e.refuse("other", "c.example.net")
	code, out := e.do(e.owner, "GET", "/v1/refused-names?source=workspace", "")
	if code != http.StatusOK {
		t.Fatalf("code %d %v", code, out)
	}
	ns := list(out["names"])
	if len(ns) != 2 {
		t.Fatalf("names = %v", ns)
	}
	var first map[string]any
	for _, n := range ns {
		if obj(n)["name"] == "a.b.example.net" {
			first = obj(n)
		}
	}
	if first["source"] != "workspace" || first["count"].(float64) != 1 || first["first"] == nil || first["last"] == nil || first["domain"] != "example.net" || first["inside"] != false {
		t.Errorf("name = %v", first)
	}
	if s, _ := first["summary"].(string); !strings.Contains(s, "a.b.example.net") {
		t.Errorf("summary = %v", first["summary"])
	}
	if c := list(first["choices"]); len(c) != 2 || obj(c[0])["id"] != "1h" || obj(c[1])["id"] != "forever" {
		t.Errorf("choices = %v", c)
	}
	opts := obj(first["options"])
	if u := list(opts["unit"]); len(u) != 3 || obj(u[0])["id"] != "name" || obj(u[1])["id"] != "domain:b.example.net" {
		t.Errorf("unit = %v", u)
	}
	for _, n := range ns {
		if obj(n)["name"] == "api.inside.example" && obj(n)["inside"] != true {
			t.Errorf("inside = %v", obj(n))
		}
	}
	if _, out := e.do(e.owner, "GET", "/v1/refused-names", ""); len(list(out["names"])) != 3 {
		t.Errorf("all sources: %v", out)
	}
}

func TestANameWithASearchSuffixIsFoldedIntoTheNameWithout(t *testing.T) {
	e := newEnv(t)
	e.withGrants()
	e.refuse("workspace", "x.example.net.svc.cluster.local", "x.example.net", "y.example.net.svc.cluster.local")
	_, out := e.do(e.owner, "GET", "/v1/refused-names", "")
	got := names(out["names"])
	if len(got) != 2 || strings.Join(got, " ") != "y.example.net.svc.cluster.local x.example.net" {
		t.Errorf("names = %v", got)
	}
}

func TestANameTheTableHasNowIsNotListed(t *testing.T) {
	e := newEnv(t)
	e.withGrants()
	e.refuse("workspace", "api.example.com", "x.example.net")
	_, out := e.do(e.owner, "GET", "/v1/refused-names", "")
	if got := names(out["names"]); len(got) != 1 || got[0] != "x.example.net" {
		t.Errorf("names = %v", got)
	}
}

func TestTheOwnerGrantsANameFromTheList(t *testing.T) {
	e := newEnv(t)
	granted := e.withGrants()
	e.refuse("workspace", "a.b.example.net")
	code, out := e.do(e.owner, "POST", "/v1/refused-names/grant", `{"source":"workspace","name":"a.b.example.net","choice":"1h","options":{"unit":"domain:example.net","handling":"passthrough"}}`)
	if code != http.StatusCreated {
		t.Fatalf("code %d %v", code, out)
	}
	g := obj(out["grant"])
	if g["kind"] != "destination" || g["name"] != "example.net" || g["unit"] != "domain" || g["handling"] != "passthrough" || g["approval"] != nil || g["access"] != nil {
		t.Errorf("grant = %v", g)
	}
	if len(*granted) != 1 {
		t.Errorf("told %d", len(*granted))
	}
	recs := e.records(audit.KindAnswer)
	if len(recs) != 1 || recs[0].Verdict != audit.Allow || recs[0].Grant != g["id"] || recs[0].Name != "a.b.example.net" || recs[0].Approval != "" ||
		!strings.Contains(recs[0].Reason, "domain:example.net") || !strings.Contains(recs[0].Reason, "passthrough") {
		t.Errorf("records = %+v", recs)
	}
	_, out = e.do(e.owner, "GET", "/v1/grants", "")
	if len(list(out["grants"])) != 1 {
		t.Errorf("grants = %v", out)
	}
	_, out = e.do(e.owner, "GET", "/v1/refused-names", "")
	if len(list(out["names"])) != 0 {
		t.Errorf("still listed: %v", out)
	}
	_, out = e.do(e.owner, "GET", "/v1/approvals?state=all", "")
	if len(list(out["approvals"])) != 0 {
		t.Errorf("an approval was made: %v", out)
	}
}

func TestGrantingFromTheListWhatCannotBeGrantedIsRefused(t *testing.T) {
	e := newEnv(t)
	e.withGrants()
	e.refuse("workspace", "a.example.net", "api.example.com")
	for _, c := range []struct {
		body string
		code int
	}{
		{`{"source":"workspace","name":"b.example.net","choice":"1h"}`, http.StatusNotFound},
		{`{"source":"other","name":"a.example.net","choice":"1h"}`, http.StatusNotFound},
		{`{"source":"workspace","name":"a.example.net","choice":"once"}`, http.StatusBadRequest},
		{`{"source":"workspace","name":"a.example.net","choice":"1h","options":{"unit":"domain:com"}}`, http.StatusBadRequest},
		{`{"source":"workspace","name":"a.example.net","choice":"1h","scope":"all"}`, http.StatusBadRequest},
		{`{"source":"workspace","name":"api.example.com","choice":"1h"}`, http.StatusBadRequest},
	} {
		if code, out := e.do(e.owner, "POST", "/v1/refused-names/grant", c.body); code != c.code {
			t.Errorf("%s: %d %v, want %d", c.body, code, out, c.code)
		}
	}
	e.log.fail = true
	if code, _ := e.do(e.owner, "POST", "/v1/refused-names/grant", `{"source":"workspace","name":"a.example.net","choice":"1h"}`); code != http.StatusServiceUnavailable {
		t.Errorf("unrecorded: %d", code)
	}
}

func TestTheWorkspaceAsksForDestinationsAsOneApproval(t *testing.T) {
	e := newEnv(t)
	e.withGrants()
	e.refuse("workspace", "docs.example.net")
	code, out := e.do(e.agent, "POST", "/v1/approvals", `{"items":[{"destination":"docs.example.net"},{"destination":"API.inside.example."}]}`)
	if code != http.StatusCreated {
		t.Fatalf("code %d %v", code, out)
	}
	if out["kind"] != "destination" || len(list(out["items"])) != 2 || out["options"] == nil {
		t.Errorf("approval = %v", out)
	}
	if c := list(out["choices"]); len(c) != 2 {
		t.Errorf("choices = %v", c)
	}
	item := obj(list(out["items"])[0])
	facts := map[string]string{}
	for _, f := range list(item["facts"]) {
		facts[obj(f)["name"].(string)] = obj(f)["value"].(string)
	}
	if item["destination"] != "docs.example.net" || facts["refusedCount"] != "1" || facts["registrableDomain"] != "example.net" || facts["inside"] != "false" {
		t.Errorf("item = %v", item)
	}
	if obj(list(out["items"])[1])["destination"] != "api.inside.example" {
		t.Errorf("the second name is not normalized: %v", list(out["items"])[1])
	}
	recs := e.records(audit.KindAgent)
	if len(recs) != 1 || recs[0].Name != "docs.example.net" || recs[0].Approval != out["id"] {
		t.Errorf("records = %+v", recs)
	}

	// The owner allows it with options.
	id := out["id"].(string)
	code, out = e.do(e.owner, "POST", "/v1/approvals/"+id+"/answer", `{"answer":"allow","choice":"forever","options":{"access":"readwrite"}}`)
	if code != http.StatusOK || len(list(out["grants"])) != 2 {
		t.Fatalf("answer: %d %v", code, out)
	}
	ans := e.records(audit.KindAnswer)
	if len(ans) != 1 || !strings.Contains(ans[0].Reason, "readwrite") || ans[0].Name != "docs.example.net" {
		t.Errorf("answer records = %+v", ans)
	}
}

func TestAskingForDestinationsThatCannotBeAskedForIsRefused(t *testing.T) {
	e := newEnv(t)
	e.withGrants()
	e.refuse("workspace", "granted.example.net")
	if _, err := e.ledger.GrantRefused(context.Background(), ledger.RefusedGrant{Source: "workspace", Name: "granted.example.net", Settings: e.table.Approvals(), Choice: "1h"}, nil); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		body string
		code int
	}{
		{`{"items":[{"destination":"api.example.com"}]}`, http.StatusBadRequest},
		{`{"items":[{"destination":"closed.example.com"}]}`, http.StatusForbidden},
		{`{"items":[{"destination":"192.0.2.1"}]}`, http.StatusBadRequest},
		{`{"items":[{"destination":"sentinel.internal"}]}`, http.StatusBadRequest},
		{`{"items":[{"destination":"com"}]}`, http.StatusBadRequest},
		{`{"items":[{"destination":"api.example.com.svc.cluster.local"}]}`, http.StatusBadRequest},
		{`{"items":[{"destination":"granted.example.net"}]}`, http.StatusBadRequest},
		{`{"items":[{"destination":"a.example.net"},{"destination":"api.example.com","operation":"pulls.merge","params":{"owner":"o","repo":"r","number":"1"}}]}`, http.StatusBadRequest},
		{`{"items":[{"destination":"a.example.net","unit":"domain"}]}`, http.StatusBadRequest},
	} {
		if code, out := e.do(e.agent, "POST", "/v1/approvals", c.body); code != c.code {
			t.Errorf("%s: %d %v, want %d", c.body, code, out, c.code)
		}
	}
}

func TestWithoutDestinationGrantsTheirDoorsAreShut(t *testing.T) {
	e := newEnv(t)
	if code, _ := e.do(e.owner, "GET", "/v1/refused-names", ""); code != http.StatusNotFound {
		t.Errorf("list: %d", code)
	}
	if code, _ := e.do(e.owner, "POST", "/v1/refused-names/grant", `{}`); code != http.StatusNotFound {
		t.Errorf("grant: %d", code)
	}
	if code, _ := e.do(e.agent, "POST", "/v1/approvals", `{"items":[{"destination":"a.example.net"}]}`); code != http.StatusBadRequest {
		t.Errorf("ask: %d", code)
	}
	_, out := e.do(e.agent, "GET", "/v1/status", "")
	if _, ok := out["refusedNames"]; ok {
		t.Errorf("status = %v", out)
	}
}

func TestOptionsOnAnAnswerToAnotherApprovalAreRefused(t *testing.T) {
	e := newEnv(t)
	e.withGrants()
	a := e.hold("workspace", "5")
	if code, _ := e.do(e.owner, "POST", "/v1/approvals/"+a.ID+"/answer", `{"answer":"allow","choice":"1h","options":{}}`); code != http.StatusBadRequest {
		t.Errorf("code %d", code)
	}
	if code, _ := e.do(e.owner, "POST", "/v1/approvals/"+a.ID+"/answer", `{"answer":"deny","options":{"unit":"name"}}`); code != http.StatusBadRequest {
		t.Errorf("deny with options: %d", code)
	}
}

func TestTheWorkspaceReadsTheNamesRecentlyRefused(t *testing.T) {
	e := newEnv(t)
	e.withGrants()
	e.refuse("workspace", "a.example.net", "a.example.net", "b.example.net.svc.cluster.local", "b.example.net")
	e.refuse("other", "c.example.net")
	_, out := e.do(e.agent, "GET", "/v1/status", "")
	rn := list(out["refusedNames"])
	if len(rn) != 2 {
		t.Fatalf("refusedNames = %v", rn)
	}
	for _, n := range rn {
		m := obj(n)
		if m["name"] == "a.example.net" && m["count"].(float64) != 2 {
			t.Errorf("a = %v", m)
		}
		if m["last"] == nil {
			t.Errorf("no last: %v", m)
		}
	}
}

func TestTheOwnerRevokesADestinationGrant(t *testing.T) {
	e := newEnv(t)
	e.withGrants()
	e.refuse("workspace", "a.example.net")
	g, err := e.ledger.GrantRefused(context.Background(), ledger.RefusedGrant{Source: "workspace", Name: "a.example.net", Settings: e.table.Approvals(), Choice: "1h"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := e.do(e.owner, "DELETE", "/v1/grants/"+g.ID, ""); code != http.StatusOK {
		t.Fatalf("code %d", code)
	}
	recs := e.records(audit.KindAnswer)
	if len(recs) != 1 || recs[0].Name != "a.example.net" || recs[0].Grant != g.ID || recs[0].Verdict != audit.Deny {
		t.Errorf("records = %+v", recs)
	}
}
