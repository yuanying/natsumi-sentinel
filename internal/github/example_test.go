package github_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yuanying/natsumi-sentinel/internal/audit"
	"github.com/yuanying/natsumi-sentinel/internal/decide"
	"github.com/yuanying/natsumi-sentinel/internal/github"
	"github.com/yuanying/natsumi-sentinel/internal/ledger"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

// githubAPI hands the questions to api.github.com to the fake.
type githubAPI struct{ h http.Handler }

func (g githubAPI) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host != "api.github.com:443" {
		return nil, errTest
	}
	rec := httptest.NewRecorder()
	g.h.ServeHTTP(rec, r)
	return rec.Result(), nil
}

// holdAll asks about everything and grants nothing.
type holdAll struct{}

func (holdAll) LookupAll(_ context.Context, fs []ledger.Facts) ([]*ledger.Grant, error) {
	return make([]*ledger.Grant, len(fs)), nil
}

func (holdAll) HoldAll(context.Context, []ledger.Facts, routes.ApprovalSettings) (*ledger.Approval, bool, error) {
	return &ledger.Approval{ID: "ap-1"}, true, nil
}

func TestTheExampleTableAllowsAsksAndDeniesAsTheFirstTableSays(t *testing.T) {
	tbl, err := routes.Load("../../examples/github")
	if err != nil {
		t.Fatal(err)
	}
	gh := &fakeGitHub{
		nodes: map[string]map[string]any{
			"R_base": {"__typename": "Repository", "name": "project", "owner": map[string]any{"login": "example-owner"}},
			"R_fork": {"__typename": "Repository", "name": "project", "owner": map[string]any{"login": "example-operator"}},
			"PR_1":   {"__typename": "PullRequest", "number": 3, "headRefOid": oidA, "repository": repoNode("example-owner", "project")},
		},
		compare: map[string]string{oidA + "..." + oidB: "diverged"},
		repos:   map[string]string{},
	}
	c := &github.Connector{Transport: githubAPI{gh}, Log: &memLog{}}
	decider := decide.Table{Ledger: holdAll{}, GitHub: c}
	decideOn := func(name, method, path, body string) audit.Verdict {
		d, ok := tbl.Lookup(name, 443)
		if !ok {
			t.Fatalf("no %s", name)
		}
		h := http.Header{}
		h.Set("Authorization", surrogate)
		return decider.Decide(context.Background(), decide.Request{
			Source: "workspace", Destination: d, Settings: tbl.Approvals(), Port: 443,
			Method: method, Path: path, Header: h, Body: []byte(body), BodyComplete: true,
		}).Verdict
	}
	for _, tc := range []struct {
		what, name, method, path, body string
		want                           audit.Verdict
	}{
		{"a read", "api.github.com", "GET", "/repos/example-owner/project/pulls", "", audit.Allow},
		{"a GraphQL read", "api.github.com", "POST", "/graphql", gql(`{ viewer { login } }`, nil), audit.Allow},
		{"a fork", "api.github.com", "POST", "/repos/example-owner/project/forks", `{}`, audit.Allow},
		{"a PR from the fork", "api.github.com", "POST", "/repos/example-owner/project/pulls", `{"head":"example-operator:fix","base":"main","title":"t"}`, audit.Allow},
		{"a PR from elsewhere", "api.github.com", "POST", "/repos/example-owner/project/pulls", `{"head":"fix","base":"main","title":"t"}`, audit.Ask},
		{"a GraphQL PR from the fork", "api.github.com", "POST", "/graphql", gql(`mutation { createPullRequest(input: {repositoryId: "R_base", headRepositoryId: "R_fork", baseRefName: "main", headRefName: "fix", title: "t"}) { clientMutationId } }`, nil), audit.Allow},
		{"a comment", "api.github.com", "POST", "/repos/example-owner/project/issues/3/comments", `{"body":"x"}`, audit.Allow},
		{"a merge", "api.github.com", "PUT", "/repos/example-owner/project/pulls/3/merge", `{"sha":"` + oidA + `"}`, audit.Ask},
		{"a GraphQL merge", "api.github.com", "POST", "/graphql", gql(`mutation { mergePullRequest(input: {pullRequestId: "PR_1", expectedHeadOid: "`+oidA+`"}) { clientMutationId } }`, nil), audit.Ask},
		{"a merge without its SHA", "api.github.com", "PUT", "/repos/example-owner/project/pulls/3/merge", `{}`, audit.Deny},
		{"a private repository", "api.github.com", "POST", "/user/repos", `{"name":"x","private":true}`, audit.Allow},
		{"a public repository", "api.github.com", "POST", "/user/repos", `{"name":"x"}`, audit.Deny},
		{"the account's settings", "api.github.com", "PATCH", "/user", `{"name":"x"}`, audit.Deny},
		{"a secret", "api.github.com", "PUT", "/repos/example-operator/project/actions/secrets/TOKEN", `{}`, audit.Deny},
		{"a webhook", "api.github.com", "POST", "/repos/example-operator/project/hooks", `{}`, audit.Deny},
		{"a deploy key", "api.github.com", "POST", "/repos/example-operator/project/keys", `{}`, audit.Deny},
		{"the visibility", "api.github.com", "PATCH", "/repos/example-operator/project", `{"private":false}`, audit.Deny},
		{"a write no rule names", "api.github.com", "POST", "/repos/example-owner/project/labels", `{}`, audit.Ask},
		{"a clone", "github.com", "POST", "/example-owner/project.git/git-upload-pack", "0000", audit.Allow},
		{"a push to its fork", "github.com", "POST", "/example-operator/project.git/git-receive-pack", push(zero + " " + oidA + " refs/heads/fix"), audit.Allow},
		{"a push elsewhere", "github.com", "POST", "/example-owner/project.git/git-receive-pack", push(zero + " " + oidA + " refs/heads/fix"), audit.Ask},
		{"a force push to main", "github.com", "POST", "/example-operator/project.git/git-receive-pack", push(oidA + " " + oidB + " refs/heads/main"), audit.Deny},
		{"a deleted branch", "github.com", "POST", "/example-operator/project.git/git-receive-pack", push(oidA + " " + zero + " refs/heads/fix"), audit.Deny},
		{"a push with a deleted branch", "github.com", "POST", "/example-operator/project.git/git-receive-pack", push(zero+" "+oidA+" refs/heads/fix", oidA+" "+zero+" refs/heads/old"), audit.Deny},
	} {
		if got := decideOn(tc.name, tc.method, tc.path, tc.body); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.what, got, tc.want)
		}
	}
}
