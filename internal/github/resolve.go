package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/yuanying/natsumi-sentinel/internal/decide"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

// nodesQuery is the one question the gate asks about node IDs: for each,
// its type and what makes it readable, for the types the gate knows
// (docs/github.md). A type not here cannot be looked up, and a mutation on
// it is refused.
const nodesQuery = `query($ids: [ID!]!) {
  nodes(ids: $ids) {
    __typename
    ... on Repository { name owner { login } }
    ... on PullRequest { number headRefOid repository { name owner { login } } }
    ... on Issue { number repository { name owner { login } } }
    ... on IssueComment { databaseId repository { name owner { login } } issue { number } }
    ... on PullRequestReview { databaseId repository { name owner { login } } pullRequest { number } }
    ... on PullRequestReviewComment { databaseId repository { name owner { login } } pullRequest { number } }
    ... on PullRequestReviewThread { repository { name owner { login } } pullRequest { number } }
    ... on Ref { name repository { name owner { login } } target { oid } }
    ... on Commit { oid repository { name owner { login } } }
    ... on Label { name repository { name owner { login } } }
    ... on User { login }
    ... on Organization { login }
  }
}`

// node is one node ID of a mutation, looked up.
type node struct {
	// arg is the argument that gave it.
	arg    string
	typ    string
	params []routes.Param
	facts  []routes.Param
}

// rank orders the types from the most particular: the node a mutation is
// on is the most particular one it names.
var rank = map[string]int{
	"IssueComment": 0, "PullRequestReview": 0, "PullRequestReviewComment": 0, "PullRequestReviewThread": 0,
	"PullRequest": 1, "Issue": 1,
	"Ref": 2, "Commit": 2, "Label": 2,
	"Repository": 3,
	"User":       4, "Organization": 4,
}

type rawNode struct {
	Typename   string      `json:"__typename"`
	Name       string      `json:"name"`
	Login      string      `json:"login"`
	Number     json.Number `json:"number"`
	DatabaseID json.Number `json:"databaseId"`
	HeadRefOid string      `json:"headRefOid"`
	Oid        string      `json:"oid"`
	Owner      *struct {
		Login string `json:"login"`
	} `json:"owner"`
	Repository *struct {
		Name  string `json:"name"`
		Owner struct {
			Login string `json:"login"`
		} `json:"owner"`
	} `json:"repository"`
	Issue *struct {
		Number json.Number `json:"number"`
	} `json:"issue"`
	PullRequest *struct {
		Number json.Number `json:"number"`
	} `json:"pullRequest"`
	Target *struct {
		Oid string `json:"oid"`
	} `json:"target"`
}

// idArgs are the arguments that hold one node ID: a string whose name
// ends in Id. Lists of IDs (labelIds) are not what a mutation is on, and
// are not looked up.
func idArgs(args map[string]any) []string {
	var names []string
	for name, v := range args {
		if !strings.HasSuffix(name, "Id") || name == "clientMutationId" {
			continue
		}
		if s, ok := v.(string); ok && s != "" {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

// lookUp asks upstream what each node ID of args is, and gives them with
// the node the mutation is on first. A node upstream does not give, or of
// a type the gate does not know, refuses the request.
func (c *Connector) lookUp(ctx context.Context, req decide.Request, args map[string]any) ([]node, string, error) {
	names := idArgs(args)
	if len(names) == 0 {
		return nil, "", nil
	}
	ids := make([]string, len(names))
	for i, n := range names {
		ids[i] = args[n].(string)
	}
	body, err := json.Marshal(map[string]any{"query": nodesQuery, "variables": map[string]any{"ids": ids}})
	if err != nil {
		return nil, "", err
	}
	var answer struct {
		Data struct {
			Nodes []*rawNode `json:"nodes"`
		} `json:"data"`
	}
	err = c.ask(ctx, req, question{method: http.MethodPost, path: "/graphql", body: body, why: "to look up the nodes a mutation names"}, decodeJSON(&answer))
	if err != nil {
		return nil, "", err
	}
	if len(answer.Data.Nodes) != len(ids) {
		return nil, "", fmt.Errorf("the answer about %d nodes had %d", len(ids), len(answer.Data.Nodes))
	}
	nodes := make([]node, len(ids))
	for i, raw := range answer.Data.Nodes {
		if raw == nil {
			return nil, fmt.Sprintf("the node %s (%s) could not be looked up upstream", names[i], ids[i]), nil
		}
		n, ok := readNode(raw)
		if !ok {
			return nil, fmt.Sprintf("the node %s is a %s, which the gate does not look up, so what the mutation is on is not known", names[i], raw.Typename), nil
		}
		n.arg = names[i]
		nodes[i] = n
	}
	slices.SortStableFunc(nodes, func(a, b node) int {
		if d := rank[a.typ] - rank[b.typ]; d != 0 {
			return d
		}
		if d := len(a.arg) - len(b.arg); d != 0 {
			return d
		}
		return strings.Compare(a.arg, b.arg)
	})
	return nodes, "", nil
}

// readNode gives a node's parameters, the owner and repository first, in
// lower case as GitHub compares them.
func readNode(r *rawNode) (node, bool) {
	n := node{typ: r.Typename}
	p := func(name, value string) { n.params = append(n.params, routes.Param{Name: name, Value: value}) }
	repo := func() bool {
		if r.Repository == nil || r.Repository.Name == "" || r.Repository.Owner.Login == "" {
			return false
		}
		p("owner", strings.ToLower(r.Repository.Owner.Login))
		p("repo", strings.ToLower(r.Repository.Name))
		return true
	}
	number := func(from *struct {
		Number json.Number `json:"number"`
	}) bool {
		if from == nil || from.Number == "" {
			return false
		}
		p("number", from.Number.String())
		return true
	}
	var ok bool
	switch r.Typename {
	case "Repository":
		ok = r.Owner != nil && r.Owner.Login != "" && r.Name != ""
		if ok {
			p("owner", strings.ToLower(r.Owner.Login))
			p("repo", strings.ToLower(r.Name))
		}
	case "PullRequest", "Issue":
		ok = repo() && r.Number != ""
		if ok {
			p("number", r.Number.String())
		}
		if r.HeadRefOid != "" {
			n.facts = append(n.facts, routes.Param{Name: "head", Value: r.HeadRefOid})
		}
	case "IssueComment":
		ok = repo() && number(r.Issue) && r.DatabaseID != ""
		if ok {
			p("comment", r.DatabaseID.String())
		}
	case "PullRequestReview", "PullRequestReviewComment":
		ok = repo() && number(r.PullRequest) && r.DatabaseID != ""
		if ok {
			name := "review"
			if r.Typename == "PullRequestReviewComment" {
				name = "comment"
			}
			p(name, r.DatabaseID.String())
		}
	case "PullRequestReviewThread":
		ok = repo() && number(r.PullRequest)
	case "Ref":
		ok = repo() && r.Name != ""
		if ok {
			p("ref", r.Name)
		}
		if r.Target != nil && r.Target.Oid != "" {
			n.facts = append(n.facts, routes.Param{Name: "commit", Value: r.Target.Oid})
		}
	case "Commit":
		ok = repo() && r.Oid != ""
		if ok {
			p("commit", r.Oid)
		}
	case "Label":
		ok = repo() && r.Name != ""
		if ok {
			p("label", r.Name)
		}
	case "User", "Organization":
		ok = r.Login != ""
		if ok {
			name := "user"
			if r.Typename == "Organization" {
				name = "org"
			}
			p(name, strings.ToLower(r.Login))
		}
	default:
		return node{}, false
	}
	if !ok {
		return node{}, false
	}
	return n, true
}
