package github

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/yuanying/natsumi-sentinel/internal/decide"
	"github.com/yuanying/natsumi-sentinel/internal/routes"
)

// rest names a REST write by the destination's rules. Merges and tags are
// GitHub's own: a merge has to name the head SHA it merges, and a tag
// shows the commit it is on and whether that is on the default branch
// (docs/adr/0005).
func (c *Connector) rest(ctx context.Context, req decide.Request) (decide.Result, error) {
	d := req.Destination
	body := routes.ParseBody(req.Body, req.BodyComplete)
	op := decide.Operation{}
	if m, ok := d.MatchRequest(req.Method, req.Path, body); ok {
		op = decide.Operation{Name: m.Operation, Params: m.Params, Target: m.Target}
	}
	parts := strings.Split(req.Path, "/")
	// /repos/{owner}/{repo}/pulls/{number}/merge
	if req.Method == http.MethodPut && len(parts) == 7 && parts[1] == "repos" && parts[4] == "pulls" && parts[6] == "merge" {
		sha, ok := body.Field("sha")
		if !ok || sha == "" || !body.IsString("sha") {
			return refuse("a merge has to name the head SHA it merges (the body's sha, read whole as JSON), so that it merges only what was looked at"), nil
		}
		op.Params = withParam(op.Params, "sha", sha)
	}
	// /repos/{owner}/{repo}/git/refs, making a tag
	if req.Method == http.MethodPost && len(parts) == 6 && parts[1] == "repos" && parts[4] == "git" && parts[5] == "refs" {
		ref, _ := body.Field("ref")
		sha, _ := body.Field("sha")
		if strings.HasPrefix(ref, "refs/tags/") && sha != "" {
			facts, refusal, err := c.tagFacts(ctx, req, strings.ToLower(parts[2]), strings.ToLower(parts[3]), sha)
			if err != nil || refusal != "" {
				return refuse(refusal), err
			}
			op.Facts = append(op.Facts, facts...)
		}
	}
	return decide.Result{Operations: []decide.Operation{op}}, nil
}

// withParam adds a parameter unless the rule already took it.
func withParam(params []routes.Param, name, value string) []routes.Param {
	for _, p := range params {
		if p.Name == name {
			return params
		}
	}
	return append(params, routes.Param{Name: name, Value: value})
}

// tagFacts looks up whether the commit a tag is put on is on the
// repository's default branch. A commit upstream does not know (one
// pushed with the tag) is told as unknown; a repository it does not know
// refuses the request.
func (c *Connector) tagFacts(ctx context.Context, req decide.Request, owner, repo, sha string) (facts []routes.Param, refusal string, err error) {
	var r struct {
		DefaultBranch string `json:"default_branch"`
	}
	err = c.ask(ctx, req, question{method: http.MethodGet, path: repoPath(owner, repo), why: "to find the default branch of the repository a tag is made in"}, decodeJSON(&r))
	if errors.Is(err, errNotFound) {
		return nil, "the repository " + owner + "/" + repo + " could not be looked up upstream", nil
	}
	if err != nil {
		return nil, "", err
	}
	if r.DefaultBranch == "" {
		return nil, "", errors.New("the repository's default branch was not in the answer")
	}
	on := "unknown"
	status, ok, err := c.compare(ctx, req, owner, repo, r.DefaultBranch, sha, "to find whether the commit a tag is put on is on the default branch")
	if err != nil {
		return nil, "", err
	}
	if ok {
		on = "false"
		if status == "behind" || status == "identical" {
			on = "true"
		}
	}
	return []routes.Param{{Name: "commit", Value: sha}, {Name: "defaultBranch", Value: r.DefaultBranch}, {Name: "onDefaultBranch", Value: on}}, "", nil
}
