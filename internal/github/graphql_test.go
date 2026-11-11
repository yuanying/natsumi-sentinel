package github_test

import (
	"errors"
	"strings"
	"testing"
)

var errTest = errors.New("the test's failure")

func TestADocumentOfQueriesOnlyGoesThroughAsARead(t *testing.T) {
	w := newWorld(t)
	for _, q := range []string{
		`{ viewer { login } }`,
		`query A { viewer { login } } query B { repository(owner:"o", name:"r") { id } }`,
		`query($n: Int!) { repository(owner:"o", name:"r") { pullRequest(number: $n) { ...F } } } fragment F on PullRequest { title }`,
	} {
		res, err := w.read("api.example.com", "POST", "/graphql", gql(q, map[string]any{"n": 1}))
		if err != nil || !res.Read {
			t.Errorf("%s: %+v, %v", q, res, err)
		}
	}
}

func TestADocumentOfAShapeTheConnectorDoesNotTakeIsRefusedWithTheReason(t *testing.T) {
	w := newWorld(t)
	for name, tc := range map[string]struct{ body, reason string }{
		"a subscription":         {gql(`subscription { x }`, nil), "subscription"},
		"two mutations":          {gql(`mutation A { a } mutation B { b }`, nil), "only operation"},
		"a mutation and a query": {gql(`mutation A { a } query B { b }`, nil), "only operation"},
		"two fields":             {gql(`mutation { a b }`, nil), "one field"},
		"a fragment at the top":  {gql(`mutation { ...F } fragment F on Mutation { a }`, nil), "one field"},
		"not GraphQL":            {gql(`mutation {`, nil), "could not be read"},
		"no operation":           {gql(`fragment F on Query { a }`, nil), "no operation"},
		"no query":               {`{"variables":{}}`, "query"},
		"a batch":                {`[` + gql(`{ a }`, nil) + `]`, "one JSON object"},
		"a field given twice":    {`{"query":"{ a }","query":"mutation { b }"}`, "twice"},
		"a variable twice":       {`{"query":"{ a }","variables":{"x":{"id":"A","id":"B"}}}`, "twice"},
		"not JSON":               {`query=x`, "one JSON object"},
	} {
		res, err := w.read("api.example.com", "POST", "/graphql", tc.body)
		if err != nil || res.Refusal == "" || !strings.Contains(res.Refusal, tc.reason) {
			t.Errorf("%s: %+v, %v; want a refusal about %q", name, res, err, tc.reason)
		}
	}
	req := w.request("api.example.com", "POST", "/graphql", gql(`{ a }`, nil))
	req.BodyComplete = false
	if res, _ := w.c.Read(t.Context(), req); res.Refusal == "" {
		t.Error("a document that was not read whole was not refused")
	}
}

func TestAMergeIsNamedByTheTableWithThePullRequestTheGateLookedUp(t *testing.T) {
	w := newWorld(t)
	w.gh.nodes["PR_1"] = map[string]any{"__typename": "PullRequest", "number": 7, "headRefOid": "head1", "repository": repoNode("Example", "R")}
	q := `mutation($input: MergePullRequestInput!) { mergePullRequest(input: $input) { pullRequest { url } } }`
	res := w.must("api.example.com", "POST", "/graphql", gql(q, map[string]any{"input": map[string]any{"pullRequestId": "PR_1", "expectedHeadOid": "head1"}}))
	if len(res.Operations) != 1 {
		t.Fatalf("operations = %+v", res.Operations)
	}
	op := res.Operations[0]
	if op.Name != "pr.merge" || params(op.Params) != "owner=example repo=r number=7 sha=head1" || strings.Join(op.Target, " ") != "owner repo number" {
		t.Errorf("operation = %+v", op)
	}
	if params(op.Facts) != "head=head1" {
		t.Errorf("facts = %s", params(op.Facts))
	}
	asked := w.gh.requests()
	if len(asked) != 1 || asked[0].Header.Get("Authorization") != surrogate || asked[0].URL.Path != "/graphql" {
		t.Errorf("asked = %+v", asked)
	}
	if len(w.log.finished) != 1 || w.log.finished[0].Request == nil || !strings.Contains(w.log.finished[0].Request.Text, "PR_1") {
		t.Errorf("the question was not recorded with what it asked: %+v", w.log.finished)
	}
}

func TestAMergeWithoutTheHeadSHAIsRefusedAsAMutation(t *testing.T) {
	w := newWorld(t)
	w.gh.nodes["PR_1"] = map[string]any{"__typename": "PullRequest", "number": 7, "headRefOid": "head1", "repository": repoNode("o", "r")}
	for _, field := range []string{"mergePullRequest", "enablePullRequestAutoMerge"} {
		q := `mutation { ` + field + `(input: {pullRequestId: "PR_1"}) { clientMutationId } }`
		res, err := w.read("api.example.com", "POST", "/graphql", gql(q, nil))
		if err != nil || !strings.Contains(res.Refusal, "SHA") {
			t.Errorf("%s: %+v, %v", field, res, err)
		}
	}
}

func TestAFieldTheTableDoesNotNameIsARawOperationNamedAfterTheFieldOnWhatItIsOn(t *testing.T) {
	w := newWorld(t)
	w.gh.nodes["R_1"] = map[string]any{"__typename": "Repository", "name": "r", "owner": map[string]any{"login": "o"}}
	res := w.must("api.example.com", "POST", "/graphql", gql(`mutation { addStar(input: {starrableId: "R_1"}) { clientMutationId } }`, nil))
	op := res.Operations[0]
	if op.Name != "graphql.addStar" || params(op.Params) != "owner=o repo=r" || strings.Join(op.Target, " ") != "owner repo" {
		t.Errorf("operation = %+v", op)
	}
}

func TestANodeThatCannotBeLookedUpIsRefused(t *testing.T) {
	w := newWorld(t)
	w.gh.nodes["P_1"] = map[string]any{"__typename": "ProjectV2"}
	for id, reason := range map[string]string{"NOPE": "could not be looked up", "P_1": "ProjectV2"} {
		res, err := w.read("api.example.com", "POST", "/graphql", gql(`mutation($id: ID!) { addComment(input: {subjectId: $id, body: "x"}) { clientMutationId } }`, map[string]any{"id": id}))
		if err != nil || !strings.Contains(res.Refusal, reason) {
			t.Errorf("%s: %+v, %v", id, res, err)
		}
	}
	w.gh.fail = true
	if _, err := w.read("api.example.com", "POST", "/graphql", gql(`mutation { addComment(input: {subjectId: "I_1", body: "x"}) { clientMutationId } }`, nil)); err == nil {
		t.Error("an upstream that does not answer was taken")
	}
}

func TestTheVariablesAndTheirDefaultsAreWhatTheMutationIsOn(t *testing.T) {
	w := newWorld(t)
	w.gh.nodes["I_9"] = map[string]any{"__typename": "Issue", "number": 9, "repository": repoNode("o", "r")}
	q := `mutation($id: ID = "I_9", $body: String!) { addComment(input: {subjectId: $id, body: $body}) { clientMutationId } }`
	res := w.must("api.example.com", "POST", "/graphql", gql(q, map[string]any{"body": "hello"}))
	op := res.Operations[0]
	if op.Name != "issue.comment" || params(op.Params) != "owner=o repo=r number=9" {
		t.Errorf("operation = %+v", op)
	}
}

func TestTheOtherNodesAMutationNamesArePrefixedByTheirArgument(t *testing.T) {
	w := newWorld(t)
	w.gh.nodes["R_base"] = map[string]any{"__typename": "Repository", "name": "r", "owner": map[string]any{"login": "o"}}
	w.gh.nodes["R_head"] = map[string]any{"__typename": "Repository", "name": "r", "owner": map[string]any{"login": "fork"}}
	q := `mutation { createPullRequest(input: {repositoryId: "R_base", headRepositoryId: "R_head", baseRefName: "main", headRefName: "x", title: "t"}) { clientMutationId } }`
	res := w.must("api.example.com", "POST", "/graphql", gql(q, nil))
	op := res.Operations[0]
	if params(op.Params) != "owner=o repo=r headRepository_owner=fork headRepository_repo=r" || strings.Join(op.Target, " ") != "owner repo" {
		t.Errorf("operation = %+v", op)
	}
}

func TestATagMadeThroughGraphQLIsNamedByItsArgumentsAndShowsItsCommit(t *testing.T) {
	w := newWorld(t)
	w.gh.nodes["R_1"] = map[string]any{"__typename": "Repository", "name": "r", "owner": map[string]any{"login": "o"}}
	w.gh.repos["o/r"] = "main"
	w.gh.compare["main...abc"] = "identical"
	q := `mutation { createRef(input: {repositoryId: "R_1", name: "refs/tags/v2", oid: "abc"}) { ref { id } } }`
	res := w.must("api.example.com", "POST", "/graphql", gql(q, nil))
	op := res.Operations[0]
	if op.Name != "tag.create" || params(op.Params) != "owner=o repo=r ref=refs/tags/v2 sha=abc tag=v2" || strings.Join(op.Target, " ") != "owner repo tag" {
		t.Errorf("operation = %+v", op)
	}
	if params(op.Facts) != "commit=abc defaultBranch=main onDefaultBranch=true" {
		t.Errorf("facts = %s", params(op.Facts))
	}
	res = w.must("api.example.com", "POST", "/graphql", gql(`mutation { createRef(input: {repositoryId: "R_1", name: "refs/heads/x", oid: "abc"}) { ref { id } } }`, nil))
	if op := res.Operations[0]; op.Name != "graphql.createRef" || len(op.Facts) != 0 {
		t.Errorf("a branch: %+v", op)
	}
}

func TestEachTypeTheGateLooksUpGivesItsParameters(t *testing.T) {
	repo := repoNode("o", "r")
	for typ, tc := range map[string]struct {
		node map[string]any
		want string
	}{
		"IssueComment":             {map[string]any{"databaseId": 11, "repository": repo, "issue": map[string]any{"number": 3}}, "owner=o repo=r number=3 comment=11"},
		"PullRequestReview":        {map[string]any{"databaseId": 12, "repository": repo, "pullRequest": map[string]any{"number": 4}}, "owner=o repo=r number=4 review=12"},
		"PullRequestReviewComment": {map[string]any{"databaseId": 13, "repository": repo, "pullRequest": map[string]any{"number": 4}}, "owner=o repo=r number=4 comment=13"},
		"PullRequestReviewThread":  {map[string]any{"repository": repo, "pullRequest": map[string]any{"number": 4}}, "owner=o repo=r number=4"},
		"Ref":                      {map[string]any{"name": "refs/heads/x", "repository": repo, "target": map[string]any{"oid": "c1"}}, "owner=o repo=r ref=refs/heads/x"},
		"Commit":                   {map[string]any{"oid": "c2", "repository": repo}, "owner=o repo=r commit=c2"},
		"Label":                    {map[string]any{"name": "bug", "repository": repo}, "owner=o repo=r label=bug"},
		"User":                     {map[string]any{"login": "Someone"}, "user=someone"},
		"Organization":             {map[string]any{"login": "Org"}, "org=org"},
	} {
		w := newWorld(t)
		tc.node["__typename"] = typ
		w.gh.nodes["N"] = tc.node
		res := w.must("api.example.com", "POST", "/graphql", gql(`mutation { doSomething(input: {nodeId: "N"}) { clientMutationId } }`, nil))
		if got := params(res.Operations[0].Params); got != tc.want {
			t.Errorf("%s: %s; want %s", typ, got, tc.want)
		}
	}
}
